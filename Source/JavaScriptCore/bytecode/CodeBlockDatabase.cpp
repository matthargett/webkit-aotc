#include "config.h"
#include "BytecodeGenerator.h"
#include "CodeBlockDatabase.h"
#include "JSCJSValueInlines.h"
#include "JSFunctionInlines.h"
#include "NodeConstructors.h"
#include "Strong.h"
#include "StrongInlines.h"
#include "UnlinkedCodeBlock.h"
#include "UnlinkedInstructionStream.h"
#include <wtf/DataLog.h>
#include <wtf/text/StringConcatenate.h>
#include <zlib.h>


#define HANDLE_FILE_ERROR() \
{  \
    dataLogF("[%s:%d:%s] file error(%d): %s\n", __FILE__, __LINE__, __FUNCTION__, errno, strerror(errno)); \
    CRASH(); \
}

#define CHECK_FILE(BOOL) \
    if (!(BOOL)) \
        HANDLE_FILE_ERROR()

#define HANDLE_ZLIB_ERROR(RC) \
{  \
    dataLogF("[%s:%d:%s] zlib error(%d): %s\n", __FILE__, __LINE__, __FUNCTION__, RC, zError(RC)); \
    CRASH(); \
}

#define CHECK_ZLIB_CODE(RC, C) \
    if (RC != (C)) \
        HANDLE_ZLIB_ERROR(RC)

#define CHECK_ZLIB_OK(RC) CHECK_ZLIB_CODE(RC, Z_OK)

namespace JSC {

const CodeFeatures ForceUsesArgumentsFeature = 1 << 8;
const CodeFeatures HasCapturedVariablesFeature = 1 << 9;
COMPILE_ASSERT(ForceUsesArgumentsFeature == AllFeatures + 1, AdditionalFeaturesAreCorrect);

static JSType getType(JSValue v) {
    ASSERT(v.isCell());
    ASSERT(v.asCell());
    ASSERT(v.asCell()->structure());
    return v.asCell()->structure()->typeInfo().type();
}

static void writeFile(FILE* f, char* data, size_t size)
{
    int rc = fwrite(data, size, 1, f);
    CHECK_FILE(rc == 1 && !ferror(f));
}

static void readFile(FILE* f, bool seek, size_t start, size_t size, Vector<char>& data)
{
    int rc;
    if (seek) {
        rc = fseek(f, start, SEEK_SET);
        CHECK_FILE(rc == 0 && !ferror(f));
    }
    ASSERT(data.size() == 0);
    data.grow(size);
    rc = fread(data.data(), size, 1, f);
    CHECK_FILE(rc == 1 && !ferror(f));
    ASSERT(data.size() == size);
}

CodeBlockDatabase::CodeBlockDatabase(const String& file_name)
    : m_scope(0)
    , m_file_name(file_name)
    , m_file(0)
    , m_fileWrite(false)
    , m_provider(0)
    , m_savingType(NoType)
    , m_strings()
    , m_constructorShift(0)
{
}

CodeBlockDatabase::~CodeBlockDatabase()
{
    if (m_file) {
        if (m_fileWrite) {
            createSearchTable();
            writeFile(m_file, m_data.data(), m_data.size());
            m_data.clear();
        }
        ASSERT(!ferror(m_file));
        int rc = fclose(m_file);
        CHECK_FILE(rc == 0);
    }
}

void CodeBlockDatabase::open(bool initDb)
{
    ASSERT(!m_file);
    m_fileWrite = initDb;
    m_file = fopen(m_file_name.utf8().data(), m_fileWrite ? "wb" : "rb");
    CHECK_FILE(m_file);
    ASSERT(m_blockIDs.size() == 0);
    ASSERT(m_data.size() == 0);
}

void CodeBlockDatabase::createSearchTable()
{
    BytesData data;
    unsigned size = (m_blockIDs.size() + 1) * (3 * sizeof(int));
    unsigned shift = size + sizeof(int);
    writeNum(data, size);
    ASSERT(m_blockIDs.size() > 0);
    ASSERT(m_blockIDs[0] == 0);
    for (unsigned i = 0; i < m_blockIDs.size(); i++) {
         writeNum(data, m_blockIDs[i]);
         writeNum(data, m_start[i] + shift);
         writeNum(data, m_origSize[i]);
    }
    writeNum(data, -1);
    writeNum(data, m_data.size() + shift);
    writeNum(data, 0);
    ASSERT(data.size() == shift);
    writeFile(m_file, data.data(), data.size());
    data.clear();
}

void CodeBlockDatabase::extractSearchTable()
{
    BytesData data;
    readFile(m_file, false, 0, sizeof(int), data);
    BytesPointer p = data.data();
    int size = readNum(&p);
    int num = size / (3 * sizeof(int));
    data.clear();
    readFile(m_file, false, sizeof(int), size, data);
    p = data.data();
    ASSERT(m_blockIDs.size() == 0);
    for (int i = 0; i < num; i++) {
        m_blockIDs.append(readNum(&p));
        m_start.append(readNum(&p));
        m_origSize.append(readNum(&p));
    }
    data.clear();
}

int CodeBlockDatabase::findStart(int blockID, int* size, int* origSize)
{
    int res = 0;
    ASSERT(m_blockIDs.size() > 0);
    for (unsigned i = 0; i < m_blockIDs.size() - 1; i++)
        if (m_blockIDs[i] == blockID) {
            res = m_start[i];
            *origSize = m_origSize[i];
            *size = m_start[i + 1] - m_start[i];
            break;
        }
    if (m_savingType != WithRun)
        RELEASE_ASSERT(res);
    return res;
}

void CodeBlockDatabase::saveProgramCodeBlock(JSScope* scope, UnlinkedProgramCodeBlock* codeBlock, ProgramExecutable* executable)
{
    m_scope = scope;
    m_programExecutable = executable;
    ASSERT(m_data.size() == 0);
    saveCodeBlock(codeBlock);
    m_programExecutable = NULL;
}

UnlinkedProgramCodeBlock* CodeBlockDatabase::loadProgramCodeBlock(JSScope* scope, ProgramExecutable* executable)
{
    m_scope = scope;
    m_programExecutable = executable;
    extractSearchTable();
    UnlinkedProgramCodeBlock* codeBlock = UnlinkedProgramCodeBlock::create(&scope->globalObject()->vm(), executable->executableInfo());
    unsigned blockID = codeBlock->getID();
    ASSERT(blockID == 0);
    if (!loadCodeBlock(codeBlock, blockID)) {
        m_programExecutable = NULL;
        return NULL;
    }
    m_programExecutable = NULL;
    return codeBlock;
}

void CodeBlockDatabase::saveFunctionCodeBlock(JSScope* scope, UnlinkedCodeBlock* codeBlock)
{
    m_scope = scope;
    saveCodeBlock(codeBlock);
}

UnlinkedFunctionCodeBlock* CodeBlockDatabase::loadFunctionCodeBlock(JSScope* scope, FunctionExecutable* executable, CodeSpecializationKind kind)
{
    m_scope = scope;
    UnlinkedFunctionCodeBlock* codeBlock = UnlinkedFunctionCodeBlock::create(&scope->globalObject()->vm(), FunctionCode, ExecutableInfo(executable->needsActivation(), executable->usesEval(), executable->isStrictMode(), kind == CodeForConstruct, false), executable->unlinkedExecutable());
    codeBlock->setSourceOffset(executable->source().startOffset());
    unsigned blockID = codeBlock->getID();
    ASSERT(blockID > 0);
    ASSERT(m_savingType != NoType);
    if (m_savingType == WithoutRun)
        blockID &= ~1; // Should load codeForCall and patch it into codeForConstruct
    if (!loadCodeBlock(codeBlock, blockID))
        return NULL;
    return codeBlock;
}

void CodeBlockDatabase::writeFunction(BytesData& data, UnlinkedFunctionExecutable* function)
{
    //dataLogF("func start offset: %d\n", function->sourceOffset());
    size_t num, len;
    BytesData temp;

    // Get data
    writeNum(data, function->sourceOffset());
    // name
    function->name().string().toBytes(temp);
    len = temp.size();
    writeNum(data, len);
    data.append(temp.data(), len);
    temp.clear();
    // inferredName
    function->inferredName().string().toBytes(temp);
    len = temp.size();
    writeNum(data, len);
    data.append(temp.data(), len);
    temp.clear();
    // options
    bool strict = function->isInStrictContext();
    bool forceUsesArguments = function->forceUsesArguments();
    CodeFeatures options = (strict ? StrictModeFeature : 0) | (forceUsesArguments ? ForceUsesArgumentsFeature : 0);
    writeNum(data, options);
    // functionMode
    writeNum(data, function->functionMode());
    // parameters
    num = function->parameters()->size();
    writeNum(data, num);
    for (size_t i = 0; i < num; ++i) {
        StringBuilder builder;
        function->parameters()->at(i)->toString(builder);
        builder.toString().toBytes(temp);
        len = temp.size();
        writeNum(data, len);
        data.append(temp.data(), len);
        temp.clear();
    }
}

UnlinkedFunctionExecutable* CodeBlockDatabase::readFunction(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ExecState* exec = m_scope->globalObject()->globalExec();
    size_t num, len;

    // Extract data
    unsigned offset = readNum(p);
    // name
    len = readNum(p);
    Identifier name = Identifier(exec, len ? String(String::ByteStreamConstructor, *p, len) : emptyString());
    *p += len;
    // inferredName
    len = readNum(p);
    Identifier inferredName = Identifier(exec, len ? String(String::ByteStreamConstructor, *p, len) : emptyString());
    *p += len;
    // options
    CodeFeatures options = readNum(p);
    bool strict = options & StrictModeFeature;
    bool forceUsesArguments = options & ForceUsesArgumentsFeature;
    // functionMode
    enum FunctionMode mode = static_cast<enum FunctionMode>(readNum(p));
    // parameters
    num = readNum(p);
    JSTextPosition start;
    JSTextPosition end;
    Vector<RefPtr<BindingNode> > nodesPtr;
    Vector<BindingNode*> nodes;
    for (size_t i = 0; i < num; i++) {
        len = readNum(p);
        Identifier ident(exec, String(String::ByteStreamConstructor, *p, len));
        *p += len;
        RefPtr<BindingNode> node = BindingNode::create(&exec->vm(), ident, start, end);
        nodesPtr.append(node);
        node->ref(); //FIXME: memory leak?
        nodes.append(node.get());
    }
    RefPtr<FunctionParameters> params = FunctionParameters::create(nodes);
    // create UnlinkedFunctionExecutable
    SourceCode source(m_provider.get(), offset);
    UnlinkedFunctionExecutable* function = UnlinkedFunctionExecutable::create(&exec->vm(), source, name, inferredName, strict, forceUsesArguments, mode, params, codeBlock->sourceOffset());
    return function;
}

void CodeBlockDatabase::writeFunctions(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t num;
    if (!codeBlock->getID()) {
        BytesData temp;
        UnlinkedProgramCodeBlock* programCodeBlock = static_cast<UnlinkedProgramCodeBlock*>(codeBlock);
        ASSERT(Options::saveBytecode() != BytecodeGenerator::saveBytecode());
        writeBool(data, Options::saveBytecode());
        writeBool(data, codeBlock->isStrictMode());
        const UnlinkedProgramCodeBlock::FunctionDeclations& functionDeclarations = programCodeBlock->functionDeclarations();
        num = functionDeclarations.size();
        writeNum(data, num);
        for (size_t i = 0; i < num; ++i)
            writeFunction(data, functionDeclarations[i].second.get());
        const UnlinkedProgramCodeBlock::VariableDeclations& variableDeclarations = programCodeBlock->variableDeclarations();
        num = variableDeclarations.size();
        writeNum(data, num);
        for (size_t i = 0; i < num; ++i) {
            writeBool(data, variableDeclarations[i].second & DeclarationStacks::IsConstant);
            variableDeclarations[i].first.string().toBytes(temp);
            size_t len = temp.size();
            writeNum(data, len);
            data.append(temp.data(), len);
            temp.clear();
        }
    } else {
        num = codeBlock->numberOfFunctionDecls();
        writeNum(data, num);
        for (size_t i = 0; i < num; i++)
            writeFunction(data, codeBlock->functionDecl(i));
    }
    num = codeBlock->numberOfFunctionExprs();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++)
        writeFunction(data, codeBlock->functionExpr(i));
}

void CodeBlockDatabase::readFunctions(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    size_t num;
    ASSERT(codeBlock->numberOfFunctionDecls() == 0);
    if (!codeBlock->getID()) {
        /*size_t nGlobalVars = readNum(p);
        if (nGlobalVars)
            globalObject->addRegisters(nGlobalVars);
        JSGlobalObject* globalObject = m_scope->globalObject();
        ASSERT(num <= nGlobalVars);
        int index = globalObject->symbolTable()->size();*/
            /* //inside following loop code
            SourceCode source(m_provider.get(), unlinkedFunction->sourceOffset());
            FunctionExecutable* function = FunctionExecutable::create(exec->vm(), source, unlinkedFunction, 0, 0, 0, 0);
            globalObject->removeDirect(exec->vm(), function->name());
            JSValue value = JSFunction::create(exec->vm(), function, m_scope);
            SymbolTableEntry entry = globalObject->symbolTable()->get(function->name().impl());
            if (!entry.isNull())
                globalObject->registerAt(entry.getIndex()).set(exec->vm(), globalObject, value);
            else {
                globalObject->registerAt(index).set(exec->vm(), globalObject, value);
                index++;
            }   FIXME: maybe need some of these stuff for multi-load */
        ExecState* exec = m_scope->globalObject()->globalExec();
        UnlinkedProgramCodeBlock* programCodeBlock = static_cast<UnlinkedProgramCodeBlock*>(codeBlock);
        ASSERT(m_savingType == NoType);
        m_savingType = readBool(p) ? WithRun : WithoutRun;
        codeBlock->setStrictMode(readBool(p));
        ASSERT(programCodeBlock->functionDeclarations().size() == 0);
        num = readNum(p);
        for (size_t i = 0; i < num; i++) {
            UnlinkedFunctionExecutable* unlinkedFunction = readFunction(p, codeBlock);
            programCodeBlock->addFunctionDeclaration(exec->vm(), unlinkedFunction->name(), unlinkedFunction);
        }
        ASSERT(programCodeBlock->functionDeclarations().size() == num);
        ASSERT(programCodeBlock->variableDeclarations().size() == 0);
        num = readNum(p);
        for (size_t i = 0; i < num; i++) {
            bool isConstant = readBool(p);
            size_t len = readNum(p);
            Identifier name = Identifier(exec, String(String::ByteStreamConstructor, *p, len));
            *p += len;
            programCodeBlock->addVariableDeclaration(name, isConstant);
        }
        ASSERT(programCodeBlock->variableDeclarations().size() == num);
        ASSERT(codeBlock->numberOfFunctionDecls() == 0);
    } else {
        num = readNum(p);
        for (size_t i = 0; i < num; i++) {
            UnlinkedFunctionExecutable* function = readFunction(p, codeBlock);
            codeBlock->addFunctionDecl(function);
        }
        ASSERT(codeBlock->numberOfFunctionDecls() == num);
    }
    ASSERT(codeBlock->numberOfFunctionExprs() == 0);
    num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        UnlinkedFunctionExecutable* function = readFunction(p, codeBlock);
        codeBlock->addFunctionExpr(function);
    }
    ASSERT(codeBlock->numberOfFunctionExprs() == num);
}

void CodeBlockDatabase::writeNum(BytesData& data, int val)
{
    data.append(static_cast<char*>(static_cast<void*>(&val)), (sizeof(int) / sizeof(char)));
}

int CodeBlockDatabase::readNum(BytesPointer* p)
{
    int val = *(static_cast<const int*>(static_cast<const void*>(*p)));
    *p += sizeof(int) / sizeof(char);
    return val;
}

void CodeBlockDatabase::writeInt64(BytesData& data, int64_t val)
{
    data.append(static_cast<char*>(static_cast<void*>(&val)), (sizeof(int64_t) / sizeof(char)));
}

int64_t CodeBlockDatabase::readInt64(BytesPointer* p)
{
    int64_t val = *(static_cast<const int64_t*>(static_cast<const void*>(*p)));
    *p += sizeof(int64_t) / sizeof(char);
    return val;
}

void CodeBlockDatabase::writeBool(BytesData& data, bool b)
{
    data.append(static_cast<char*>(static_cast<void*>(&b)), (sizeof(bool) / sizeof(char)));
}

bool CodeBlockDatabase::readBool(BytesPointer* p)
{
    bool b = *(static_cast<const bool*>(static_cast<const void*>(*p)));
    *p += sizeof(bool) / sizeof(char);
    return b;
}

void CodeBlockDatabase::writeEncodedJSValue(BytesData& data, EncodedJSValue ev)
{
    data.append(static_cast<char*>(static_cast<void*>(&ev)), sizeof(EncodedJSValue) / sizeof(char));
}

EncodedJSValue CodeBlockDatabase::readEncodedJSValue(BytesPointer* p)
{
    EncodedJSValue ev = *(static_cast<const EncodedJSValue*>(static_cast<const void*>(*p)));
    *p += sizeof(EncodedJSValue) / sizeof(char);
    return ev;
}

void CodeBlockDatabase::writeCodeBlockInternals(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    if (codeBlock->getID()) { // Save UnlinkedFunctionExecutable features
        UnlinkedFunctionExecutable* function = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        int features = function->features();
        features |= function->hasCapturedVariables() ? HasCapturedVariablesFeature : 0;
        writeNum(data, features);
        writeNum(data, codeBlock->activationRegister().offset());
    } else { // Save ProgramExecutable features
        ASSERT(m_programExecutable);
        int features = m_programExecutable->features();
        features |= m_programExecutable->hasCapturedVariables() ? HasCapturedVariablesFeature : 0;
        writeNum(data, features);
    }

    // Save UnlinkedCodeBlock info
    writeNum(data, codeBlock->m_numCalleeRegisters);
    writeNum(data, codeBlock->m_numVars);
    writeNum(data, codeBlock->m_thisPlace);
    writeNum(data, codeBlock->m_thisPlaceRegister);
    writeNum(data, codeBlock->numParameters());
    writeBool(data, codeBlock->isLastReturnFixed());
    writeBool(data, codeBlock->needsFullScopeChain());
    writeNum(data, codeBlock->argumentsRegister().offset());

    writeNum(data, codeBlock->numberOfValueProfiles());
    writeNum(data, codeBlock->numberOfArrayProfiles());
    writeNum(data, codeBlock->numberOfArrayAllocationProfiles());
    writeNum(data, codeBlock->numberOfObjectAllocationProfiles());
    writeNum(data, codeBlock->numberOfLLintCallLinkInfos());
}

void CodeBlockDatabase::readCodeBlockInternals(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    if (codeBlock->getID()) { // Load UnlinkedFunctionExectable features
        UnlinkedFunctionExecutable* function = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        int features = readNum(p);
        ASSERT(function->isInStrictContext() == !!(features & StrictModeFeature));
        ASSERT(codeBlock->isStrictMode() == function->isInStrictContext());
        function->recordParse(features & AllFeatures, features & HasCapturedVariablesFeature);
        codeBlock->recordParse(features & AllFeatures, features & HasCapturedVariablesFeature, 0, 0, 0, true);
        codeBlock->setActivationRegister(VirtualRegister(readNum(p)));
    } else { // Load ProgramExecutable features
        ASSERT(m_programExecutable);
        int features = readNum(p);
        m_programExecutable->recordParse(features & AllFeatures, features & HasCapturedVariablesFeature, 0, 0, 0, 0);
        codeBlock->recordParse(features & AllFeatures, features & HasCapturedVariablesFeature, 0, 0, 0, true);
    }

    // Load UnlinkedCodeBlock info
    codeBlock->m_numCalleeRegisters = readNum(p);
    codeBlock->m_numVars = readNum(p);
    codeBlock->m_thisPlace = readNum(p);
    codeBlock->m_thisPlaceRegister = readNum(p);
    codeBlock->setNumParameters(readNum(p));
    if (readBool(p)) codeBlock->setLastReturnFixed();
    codeBlock->setNeedsFullScopeChain(readBool(p));
    codeBlock->setArgumentsRegister(VirtualRegister(readNum(p)));

    codeBlock->setNumberOfValueProfiles(readNum(p));
    codeBlock->setNumberOfArrayProfiles(readNum(p));
    codeBlock->setNumberOfArrayAllocationProfiles(readNum(p));
    codeBlock->setNumberOfObjectAllocationProfiles(readNum(p));
    codeBlock->setNumberOfLLintCallLinkInfos(readNum(p));
}

void CodeBlockDatabase::writeJumpTargets(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t num = codeBlock->numberOfJumpTargets();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++)
        writeNum(data, codeBlock->jumpTarget(i));
}

void CodeBlockDatabase::readJumpTargets(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfJumpTargets() == 0);
    size_t num = readNum(p);
    for (size_t i = 0; i < num; i++)
        codeBlock->addJumpTarget(constructorShift(readNum(p), codeBlock));
    ASSERT(codeBlock->numberOfJumpTargets() == num);
}

void CodeBlockDatabase::writeObject(BytesData& data, JSValue v, bool fromCache)
{
    bool isCell = v.isCell();
    writeBool(data, isCell);
    if (!isCell)
        writeEncodedJSValue(data, JSValue::encode(v));
    else {
        ExecState* exec = m_scope->globalObject()->globalExec();
        BytesData temp;
        size_t len;
        if (v.asCell() == NULL) {
            writeNum(data, LastJSCObjectType + 1);
            return;
        }
        JSType t = getType(v);
        writeNum(data, t);
        switch (t) {
        case GlobalObjectType:
            break;
        case StringType:
            if (fromCache) {
                unsigned found = m_strings.size();
                for (unsigned i = 0; i < m_strings.size(); i++) {
                    if (asString(v) == m_strings[i]) {
                        found = i;
                        break;
                    }
                }
                ASSERT(found < m_strings.size());
                //dataLogF("Cached %u\n", found);
                writeNum(data, found);
            } else {
                m_strings.append(asString(v));
                asString(v)->value(exec).toBytes(temp);
                len = temp.size();
                writeNum(data, len);
                data.append(temp.data(), len);
                temp.clear();
            }
            break;
        case FinalObjectType:
            ASSERT(v == JSValue(exec->vm().iterationTerminator.get()));
            break;
        default:
            dataLogF("Not implemented\n");
            RELEASE_ASSERT_NOT_REACHED();
            break;
        }
    }
}

JSValue CodeBlockDatabase::readObject(BytesPointer* p, bool fromCache)
{
    bool b = readBool(p);
    JSValue v;
    if (b) {
        ExecState* exec = m_scope->globalObject()->globalExec();
        size_t len;
        unsigned number = readNum(p);
        if (number == LastJSCObjectType + 1)
            return JSValue();
        JSType t = static_cast<JSType>(number);
        switch (t) {
        case GlobalObjectType:
            v = JSValue(m_scope->globalObject());
            break;
        case StringType:
            if (fromCache) {
                unsigned found = readNum(p);
                //dataLogF("FromCache %u\n", found);
                v = m_strings[found];
            } else {
                len = readNum(p);
                v = JSValue(jsOwnedString(exec, String(String::ByteStreamConstructor, *p, len)));
                *p += len;
                m_strings.append(v);
            }
            break;
        case FinalObjectType:
            v = JSValue(exec->vm().iterationTerminator.get());
            break;
        default:
            RELEASE_ASSERT_NOT_REACHED();
            break;
        }
    } else
        v = JSValue::decode(readEncodedJSValue(p));
    return v;
}

void CodeBlockDatabase::writeConstants(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t elems, num = codeBlock->numberOfConstantRegisters();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++)
        writeObject(data, codeBlock->getConstant(FirstConstantRegisterIndex + i), false);

    num = codeBlock->numberOfConstantBuffers();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        elems = codeBlock->getConstantBufferSize(i);
        writeNum(data, elems);
        for (size_t j = 0; j < elems; j++)
            writeObject(data, codeBlock->constantBuffer(i).at(j), true);
    }
    m_strings.clear();
}

void CodeBlockDatabase::readConstants(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    m_strings.clear();
    ASSERT(codeBlock->numberOfConstantRegisters() == 0);
    size_t elems, num = readNum(p);
    for (size_t i = 0; i < num; i++)
        codeBlock->addConstant(readObject(p, false));
    ASSERT(codeBlock->numberOfConstantRegisters() == num);

    ASSERT(codeBlock->numberOfConstantBuffers() == 0);
    num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        elems = readNum(p);
        size_t index = codeBlock->addConstantBuffer(elems);
        ASSERT(index == i);
        UnlinkedCodeBlock::ConstantBuffer& buffer = codeBlock->constantBuffer(index);
        for (size_t j = 0; j < elems; j++)
            buffer[j] = readObject(p, true);
    }
    ASSERT(codeBlock->numberOfConstantBuffers() == num);
}

void CodeBlockDatabase::writeSymbolTable(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    if (codeBlock->getID()) {
        BytesData temp;
        size_t elems;
        SymbolTable* symbolTable = codeBlock->symbolTable();
        ASSERT(symbolTable);
        UnlinkedFunctionExecutable* function = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        ConcurrentJITLocker locker(symbolTable->m_lock);
        writeNum(data, symbolTable->captureStart());
        writeNum(data, symbolTable->captureEnd());

        const SlowArgument* slowArguments = symbolTable->slowArguments();
        writeBool(data, !!slowArguments);
        if (slowArguments) {
            unsigned parameterCount = symbolTable->parameterCount();
            ASSERT_UNUSED(function, function->parameters()->size() == parameterCount);
            for (unsigned i = 0; i < parameterCount; ++i) {
                writeNum(data, slowArguments[i].status);
                writeNum(data, slowArguments[i].index);
            }
        }
        writeNum(data, symbolTable->size(locker));
        for (SymbolTable::Map::iterator iter = symbolTable->begin(locker), end = symbolTable->end(locker); iter != end; ++iter) {
             writeInt64(data, iter->value.getBits());
             iter->key.get()->toBytes(temp);
             elems = temp.size();
             writeNum(data, elems);
             data.append(temp.data(), elems);
             temp.clear();
        }
    } else
        ASSERT(!codeBlock->symbolTable());
}

void CodeBlockDatabase::readSymbolTable(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    if (codeBlock->getID()) {
        ExecState* exec = m_scope->globalObject()->globalExec();
        UnlinkedFunctionExecutable* function = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        size_t elems, num;
        SymbolTable* symbolTable = codeBlock->symbolTable();
        ASSERT(symbolTable);
        ASSERT(symbolTable->size() == 0);
        ConcurrentJITLocker locker(symbolTable->m_lock);
        symbolTable->setCaptureStart(readNum(p));
        symbolTable->setCaptureEnd(readNum(p));
        symbolTable->setUsesNonStrictEval(codeBlock->usesEval() && !codeBlock->isStrictMode());
        symbolTable->setParameterCountIncludingThis(function->parameters()->size() + 1);

        if (readBool(p)) {
            unsigned parameterCount = symbolTable->parameterCount();
            auto slowArguments = std::make_unique<SlowArgument[]>(parameterCount);
            for (unsigned i = 0; i < parameterCount; ++i) {
                ASSERT(slowArguments[i].status == SlowArgument::Normal);
                slowArguments[i].status = static_cast<enum SlowArgument::Status>(readNum(p));
                slowArguments[i].index = readNum(p);
            }
            symbolTable->setSlowArguments(std::move(slowArguments));
        }


        num = readNum(p);
        for (size_t i = 0; i < num; i++) {
            SymbolTableEntry entry = SymbolTableEntry(SymbolTableEntry::Bits, readInt64(p));
            elems = readNum(p);
            Identifier ident(exec, String(String::ByteStreamConstructor, *p, elems));
            *p += elems;
            SymbolTable::Map::AddResult result = symbolTable->add(locker, ident.impl(), entry);
            ASSERT_UNUSED(result, result.isNewEntry);
        }
    } else
        ASSERT(!codeBlock->symbolTable());
}

void CodeBlockDatabase::writeIdentifiers(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    BytesData temp;
    unsigned num = codeBlock->numberOfIdentifiers();
    int elems;
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        if(codeBlock->identifier(i).length() == 0 && codeBlock->identifier(i).impl() != emptyString().impl()) {
            Identifier pub = codeBlock->vm()->propertyNames->getPublicName(codeBlock->identifier(i));
            pub.string().toBytes(temp);
            elems = temp.size();
            RELEASE_ASSERT(elems > 1);
            ASSERT(elems == 9 || elems == 13); //FIXME: something else but "iterator" or "iteratorNext" ???
            writeNum(data, -elems);
        } else {
            codeBlock->identifier(i).string().toBytes(temp);
            elems = temp.size();
            writeNum(data, elems);
        }
        data.append(temp.data(), elems);
        temp.clear();
    }
}

void CodeBlockDatabase::readIdentifiers(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfIdentifiers() == 0);
    ExecState* exec = m_scope->globalObject()->globalExec();
    unsigned num = readNum(p);
    int elems;
    for (size_t i = 0; i < num; i++) {
        elems = readNum(p);
        if (elems < 0) {
            Identifier pub(exec, String(String::ByteStreamConstructor, *p, -elems));
            *p += (-elems);
            const Identifier* ident = codeBlock->vm()->propertyNames->getPrivateName(pub);
            ASSERT(ident);
            codeBlock->addIdentifier(*ident);
        } else {
            Identifier ident(exec, String(String::ByteStreamConstructor, *p, elems));
            *p += elems;
            codeBlock->addIdentifier(ident);
        }
    }
    ASSERT(codeBlock->numberOfIdentifiers() == num);
}

void CodeBlockDatabase::writeImmediateSwitchTables(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t elems, num = codeBlock->numberOfSwitchJumpTables();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        UnlinkedSimpleJumpTable& table = codeBlock->switchJumpTable(i);
        writeNum(data, table.min);
        elems = table.branchOffsets.size();
        writeNum(data, elems);
        for (size_t j = 0; j < elems; j++)
            writeNum(data, table.branchOffsets[j]);
    }
}

void CodeBlockDatabase::readImmediateSwitchTables(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfSwitchJumpTables() == 0);
    size_t elems, num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        codeBlock->addSwitchJumpTable();
        codeBlock->switchJumpTable(i).min = readNum(p);
        elems = readNum(p);
        for (size_t j = 0; j < elems; j++)
             codeBlock->switchJumpTable(i).branchOffsets.append(readNum(p));
    }
    ASSERT(codeBlock->numberOfSwitchJumpTables() == num);
}

void CodeBlockDatabase::writeStringSwitchTables(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    BytesData temp;
    size_t len, elems, num = codeBlock->numberOfStringSwitchJumpTables();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        UnlinkedStringJumpTable& table = codeBlock->stringSwitchJumpTable(i);
        elems = table.offsetTable.size();
        writeNum(data, elems);
        UnlinkedStringJumpTable::StringOffsetTable::const_iterator iter;
        for (iter = table.offsetTable.begin(); iter != table.offsetTable.end(); ++iter) {
            writeNum(data, iter->value);
            iter->key.get()->toBytes(temp);
            len = temp.size();
            writeNum(data, len);
            data.append(temp.data(), len);
            temp.clear();
            elems--;
        }
        ASSERT(elems == 0);
    }
}

void CodeBlockDatabase::readStringSwitchTables(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfStringSwitchJumpTables() == 0);
    size_t len, elems, num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        codeBlock->addStringSwitchJumpTable();
        elems = readNum(p);
        for (size_t j = 0; j < elems; j++) {
             int32_t location;
             location = readNum(p);
             len = readNum(p);
             String str = String(String::ByteStreamConstructor, *p, len);
             *p += len;
             codeBlock->stringSwitchJumpTable(i).offsetTable.add(str.impl(), location);
        }
    }
    ASSERT(codeBlock->numberOfStringSwitchJumpTables() == num);
}

void CodeBlockDatabase::writeSwitches(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    writeImmediateSwitchTables(data, codeBlock);
    writeStringSwitchTables(data, codeBlock);
}

void CodeBlockDatabase::readSwitches(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    readImmediateSwitchTables(p, codeBlock);
    readStringSwitchTables(p, codeBlock);
}

void CodeBlockDatabase::writeBytecode(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    writeNum(data, codeBlock->instructions().count());
    writeNum(data, codeBlock->instructions().byteSize());
    data.append(codeBlock->instructionsPointer()->data(), codeBlock->instructionsPointer()->byteSize());
}

void CodeBlockDatabase::readBytecode(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    unsigned instructionCount = readNum(p);
    unsigned byteSize = readNum(p);
    bool reconstruct = (m_savingType == WithoutRun) && codeBlock->isConstructor();
    ASSERT(!reconstruct || codeBlock->getID());
    ASSERT(NULL == codeBlock->instructionsPointer());
    Vector<unsigned char> data;
    data.append(*p, byteSize);
    *p += byteSize;
    m_constructorShift = 0;
    if (!reconstruct)
        codeBlock->setInstructions(std::make_unique<UnlinkedInstructionStream>(instructionCount, data));
    else {
        ExecState* exec = m_scope->globalObject()->globalExec();
        VM& vm = exec->vm();
        unsigned thisIndex = codeBlock->thisRegister().offset();
        UnlinkedInstructionStream buffer = UnlinkedInstructionStream(instructionCount, data);
        UnlinkedInstructionStream::Reader reader(buffer);
        Vector<UnlinkedInstruction, 0, UnsafeVectorOverflow> instructions(instructionCount+opcodeLengths[op_get_callee] + opcodeLengths[op_create_this]);

#if !ASSERT_DISABLED
        int numFixes = 0;
#endif
        int base = 0, num = instructionCount;
        while (base < num) {
            if (base == codeBlock->m_thisPlace) {
                int temp = codeBlock->m_thisPlaceRegister;
                instructions[base].u.opcode = op_get_callee;
                instructions[base + 1].u.operand = temp;
                instructions[base + 2].u.index = 0;
                instructions[base + 3].u.opcode = op_create_this;
                instructions[base + 4].u.index = thisIndex;
                instructions[base + 5].u.operand = temp;
                instructions[base + 6].u.index = 0;
                ASSERT(m_constructorShift == 0);
                m_constructorShift = 7;
                num += 7;
                base += 7;
#if !ASSERT_DISABLED
                numFixes++;
#endif
            }

            ASSERT(!reader.atEnd());
            const UnlinkedInstruction* pc = reader.next();
            OpcodeID opcodeID = pc[0].u.opcode;
            int length = opcodeLengths[opcodeID];
            for (int j = 0; j < length; j++)
                instructions[base + j] = pc[j];

            switch(opcodeID) {
                case op_ret: {
                    ASSERT(instructions[base + 2].u.index == 0);
                    if (codeBlock->isLastReturnFixed() && base + length == num) {
#if !ASSERT_DISABLED
                        unsigned index = instructions[base + 1].u.index;
                        ASSERT(codeBlock->isConstantRegisterIndex(index));
                        ASSERT(codeBlock->constantRegister(index).get().isUndefined());
#endif
                        instructions[base + 1].u.index = thisIndex;
                    } else if (instructions[base + 1].u.index != thisIndex) {
                        instructions[base].u.opcode = op_ret_object_or_this;
                        instructions[base + 2].u.index = thisIndex;
                    }
                    break;
                }
                case op_to_this: {
                    ASSERT(instructions[base + 1].u.index == thisIndex);
                    int temp = codeBlock->m_thisPlaceRegister;
                    instructions[base].u.opcode = op_get_callee;
                    instructions[base + 1].u.operand = temp;
                    ASSERT(instructions[base + 2].u.index == 0);
                    instructions[base + 3].u.opcode = op_create_this;
                    instructions[base + 4].u.index = thisIndex;
                    instructions[base + 5].u.operand = temp;
                    instructions[base + 6].u.index = 0;
                    ASSERT(codeBlock->m_thisPlace == -1);
                    codeBlock->m_thisPlace = base;
                    ASSERT(m_constructorShift == 0);
                    m_constructorShift = 4;
                    num += 4;
                    base += 4;
#if !ASSERT_DISABLED
                    numFixes++;
#endif
                    break;
                }
                default:
                    break;
            } // switch
            base += length;
        } //while
#if !ASSERT_DISABLED
        ASSERT(reader.atEnd());
        ASSERT(numFixes == 1);
#endif
        instructions.shrink(num);
        codeBlock->setInstructions(std::make_unique<UnlinkedInstructionStream>(instructions));
    }
}

void CodeBlockDatabase::writeExceptionHandlers(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t num = codeBlock->numberOfExceptionHandlers();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        UnlinkedHandlerInfo& info = codeBlock->exceptionHandler(i);
        writeNum(data, info.start);
        writeNum(data, info.end);
        writeNum(data, info.target);
        writeNum(data, info.scopeDepth);
    }
}

unsigned CodeBlockDatabase::constructorShift(unsigned offset, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(m_constructorShift == 0 || codeBlock->m_thisPlace >= 0);
    if (static_cast<int>(offset) < codeBlock->m_thisPlace) {
        return offset;
    } else {
        return offset + m_constructorShift;
    }
}

void CodeBlockDatabase::readExceptionHandlers(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfExceptionHandlers() == 0);
    size_t num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        uint32_t start = constructorShift(readNum(p), codeBlock);
        uint32_t end = constructorShift(readNum(p), codeBlock);
        uint32_t target = constructorShift(readNum(p), codeBlock);
        uint32_t scopeDepth = readNum(p);
        UnlinkedHandlerInfo info = { start, end, target, scopeDepth };
        codeBlock->addExceptionHandler(info);
    }
    ASSERT(codeBlock->numberOfExceptionHandlers() == num);
}

void CodeBlockDatabase::writeRegExps(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    BytesData temp;
    size_t elems, num = codeBlock->numberOfRegExps();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        RegExp *regexp = codeBlock->regexp(i);
        unsigned flags = NoFlags;
        if (regexp->global())
            flags |= FlagGlobal;
        if (regexp->ignoreCase())
            flags |= FlagIgnoreCase;
        if (regexp->multiline())
            flags |= FlagMultiline;
        writeNum(data, flags);
        regexp->pattern().toBytes(temp);
        elems = temp.size();
        writeNum(data, elems);
        data.append(temp.data(), elems);
        temp.clear();
    }
}

void CodeBlockDatabase::readRegExps(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfRegExps() == 0);
    size_t elems, num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        RegExpFlags flags = static_cast<RegExpFlags>(readNum(p));
        elems = readNum(p);
        codeBlock->addRegExp(RegExp::create(*codeBlock->vm(), String(String::ByteStreamConstructor, *p, elems), flags));
        *p += elems;
    }
    ASSERT(codeBlock->numberOfRegExps() == num);
}

void CodeBlockDatabase::saveCodeBlock(UnlinkedCodeBlock* codeBlock)
{
    int rc, origSize;
    unsigned blockID = codeBlock->getID();
    ASSERT(codeBlock->codeType() == ((blockID == 0) ? GlobalCode : FunctionCode));
    //dataLogF("save block=%d offset=%d constructor=%d\n", blockID, blockID/2, blockID%2);
    ASSERT(m_blockIDs.size() == m_start.size());
    BytesData data;

    // Create data
    writeFunctions(data, codeBlock);
    writeCodeBlockInternals(data, codeBlock);
    writeConstants(data, codeBlock);
    writeSymbolTable(data, codeBlock);
    writeIdentifiers(data, codeBlock);
    writeBytecode(data, codeBlock);
    writeJumpTargets(data, codeBlock);
    writeSwitches(data, codeBlock);
    writeExceptionHandlers(data, codeBlock);
    writeRegExps(data, codeBlock);

    // For search table
    size_t start = m_data.size();
    m_start.append(start);
    m_blockIDs.append(blockID);
    origSize = data.size();

    // Space for zlib
    m_data.grow(start + origSize - 1);

    z_stream ds;
    ds.zalloc = Z_NULL;
    ds.zfree = Z_NULL;
    ds.opaque = Z_NULL;
    ds.avail_in = origSize; // size of input
    ds.next_in = reinterpret_cast<uint8_t*>(data.data()); // input
    ds.avail_out = origSize - 1; // size of output
    ds.next_out = reinterpret_cast<uint8_t*>(&m_data[start]); // output

    rc = deflateInit(&ds, Options::compression());
    CHECK_ZLIB_OK(rc);
    rc = deflate(&ds, Z_FINISH);
    if (rc == Z_STREAM_END) { // compressed succesfully
        size_t newSize = ds.next_out - reinterpret_cast<uint8_t*>(&m_data[start]);
        m_data.shrink(start + newSize);
        rc = deflateEnd(&ds);
        CHECK_ZLIB_OK(rc);
    } else { // not enough place
        CHECK_ZLIB_OK(rc);
        rc = deflateReset(&ds);
        CHECK_ZLIB_OK(rc);
        rc = deflateEnd(&ds);
        CHECK_ZLIB_OK(rc);
        m_data.shrink(start);
        m_data.append(data.data(), origSize);
        origSize = -1;
    }
    m_origSize.append(origSize);
}

bool CodeBlockDatabase::loadCodeBlock(UnlinkedCodeBlock* codeBlock, unsigned blockID)
{
    //dataLogF("load BlockID: %d\n", blockID);
    codeBlock->setThisRegister(RegisterID(CallFrame::thisArgumentOffset()).virtualRegister());
    ASSERT(codeBlock->codeType() == ((blockID == 0) ? GlobalCode : FunctionCode));
    BytesData c_data;
    BytesData u_data;
    BytesPointer p = 0;
    int size = 0, origSize = 0, start;
    // Find info
    start = findStart(blockID, &size, &origSize);
    if (start == 0) {
        ASSERT(m_savingType == WithRun);
        return false;
    }
    ASSERT(size > 0);
    ASSERT(origSize != 0);
    readFile(m_file, blockID > 0, start, size, c_data);

    if (origSize != -1) {
        u_data.grow(origSize);
        z_stream ps;
        ps.zalloc = Z_NULL;
        ps.zfree = Z_NULL;
        ps.opaque = Z_NULL;
        ps.avail_in = size; // size of input
        ps.next_in = reinterpret_cast<uint8_t*>(c_data.data()); // input char array
        ps.avail_out = origSize; // size of output
        ps.next_out = reinterpret_cast<uint8_t*>(u_data.data()); // output char array

        int rc = inflateInit(&ps);
        CHECK_ZLIB_OK(rc);
        rc = inflate(&ps, Z_FINISH);
        CHECK_ZLIB_CODE(rc, Z_STREAM_END);
        rc = inflateEnd(&ps);
        CHECK_ZLIB_OK(rc);
        c_data.clear();
        p = u_data.data();
    } else {
        p = c_data.data();
    }
    ASSERT(p);
    // Extract data
    readFunctions(&p, codeBlock);
    readCodeBlockInternals(&p, codeBlock);
    readConstants(&p, codeBlock);
    readSymbolTable(&p, codeBlock);
    readIdentifiers(&p, codeBlock);
    readBytecode(&p, codeBlock);
    readJumpTargets(&p, codeBlock);
    readSwitches(&p, codeBlock);
    readExceptionHandlers(&p, codeBlock);
    readRegExps(&p, codeBlock);

    // Check total bytes
    ASSERT(origSize == -1 ? p == c_data.data() + c_data.size() : p == u_data.data() + u_data.size());
    return true;
}

} // namespace JSC
