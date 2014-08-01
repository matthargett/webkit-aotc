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

const CodeBlockDatabase::PatchInfo CodeBlockDatabase::c_patch_infos[] = {
/*    { op_get_global_var, 2},
    { op_get_global_var_watchable, 2},
    { op_put_global_var, 1},
    { op_put_global_var_check, 1}*/
};
const int CodeBlockDatabase::c_n_patch_info = sizeof(c_patch_infos)/sizeof(PatchInfo);

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
    ASSERT(res);
    return res;
}

void CodeBlockDatabase::saveProgramCodeBlock(JSScope* scope, UnlinkedProgramCodeBlock* codeBlock)
{
    m_scope = scope;
    ASSERT(m_data.size() == 0);
    saveCodeBlock(codeBlock);
}

UnlinkedProgramCodeBlock* CodeBlockDatabase::loadProgramCodeBlock(JSScope* scope, ProgramExecutable* executable)
{
    m_scope = scope;
    m_programExecutable = executable;
    extractSearchTable();
    UnlinkedProgramCodeBlock* codeBlock = UnlinkedProgramCodeBlock::create(&scope->globalObject()->vm(), executable->executableInfo());
    codeBlock->setSymbolTable(scope->globalObject()->symbolTable());
    //recordParse???
    unsigned blockID = codeBlock->getID();
    ASSERT(blockID == 0);
    loadCodeBlock(codeBlock, blockID);
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
    /*if (m_savingType == WithoutRun)
        blockID &= ~1; // Should load codeForCall and patch it into codeForConstruct*/
    loadCodeBlock(codeBlock, blockID);
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
//  const char* z = 0;

    // Extract data
    unsigned offset = readNum(p);
    // name
    len = readNum(p);
    Identifier name = Identifier(exec, len ? String(String::ByteStreamConstructor, *p, len) : emptyString());
    *p += len;
    // inferredName
    len = readNum(p);
    Identifier inferredName = Identifier(exec, len ? String(String::ByteStreamConstructor, *p, len) : emptyString());
//    Identifier inferredName = len ? Identifier(exec, String(String::ByteStreamConstructor, *p, len)) : Identifier(exec, z);
    *p += len;
    // options
    CodeFeatures options = readNum(p);
    bool strict = options & StrictModeFeature;
    bool forceUsesArguments = options & ForceUsesArgumentsFeature;
    SourceCode source(m_provider.get(), offset);
    //parameters
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
    UnlinkedFunctionExecutable* function = UnlinkedFunctionExecutable::create(&exec->vm(), source, name, inferredName, strict, forceUsesArguments, params, codeBlock->sourceOffset());
    return function;
}

void CodeBlockDatabase::writeFunctions(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t num;
    bool global = (codeBlock->getID() == 0);
    ASSERT(codeBlock->codeType() == global ? GlobalCode : FunctionCode);
    if (global) {
        num = 0;
        BytesData temp;
        JSGlobalObject* globalObject = m_scope->globalObject();
        const int excluded_n = 6;
        ASSERT(Options::saveBytecode() != BytecodeGenerator::saveBytecode());
        writeBool(data, Options::saveBytecode());
        writeBool(data, codeBlock->isStrictMode());
        writeNum(data, globalObject->numberOfRegisters() - excluded_n);
        for (size_t i = excluded_n; i < globalObject->numberOfRegisters(); ++i) {
            JSValue v = globalObject->registerAt(i).get();
            if (v.isUndefined())
                continue;
            if (!v.isCell() || getType(v) != JSFunctionType) {
                dataLogF("Not implemented\n");
                ASSERT_NOT_REACHED();
                CRASH();
            }
            writeFunction(temp, jsCast<JSFunction*>(v)->jsExecutable()->unlinkedExecutable());
            num++;
        }
        writeNum(data, num);
        data.append(temp.data(), temp.size());
        temp.clear();
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
    bool global = (codeBlock->getID() == 0);
    ASSERT(codeBlock->codeType() == global ? GlobalCode : FunctionCode);
    if (global) {
        JSGlobalObject* globalObject = m_scope->globalObject();
        ExecState* exec = m_scope->globalObject()->globalExec();

        ASSERT(m_savingType == NoType);
        m_savingType = readBool(p) ? WithRun : WithoutRun;
        codeBlock->setStrictMode(readBool(p));
        size_t nGlobalVars = readNum(p);
        if (nGlobalVars)
            globalObject->addRegisters(nGlobalVars);
        num = readNum(p);
        ASSERT(num <= nGlobalVars);
        int index = globalObject->symbolTable()->size();
        for (size_t i = 0; i < num; i++) {
            UnlinkedFunctionExecutable* unlinkedFunction = readFunction(p, codeBlock);
            (static_cast<UnlinkedProgramCodeBlock*>(codeBlock))->addFunctionDeclaration(exec->vm(), unlinkedFunction->name(), unlinkedFunction);
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
            }
        }
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

/*void CodeBlockDatabase::writeInsn(BytesData& data, Instruction insn)
{
    data.append(static_cast<char*>(static_cast<void*>(&insn)), sizeof(Instruction) / sizeof(char));
}

Instruction CodeBlockDatabase::readInsn(BytesPointer* p)
{
    Instruction insn = *(static_cast<const Instruction*>(static_cast<const void*>(*p)));
    *p += sizeof(Instruction) / sizeof(char);
    return insn;
}*/

void CodeBlockDatabase::writeCodeBlockInternals(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    if (codeBlock->getID()) { // Save UnlinkedFunctionExecutable features
        ASSERT(codeBlock->codeType() == FunctionCode);
        UnlinkedFunctionExecutable *func = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        int features = func->features();
        features |= func->hasCapturedVariables() ? HasCapturedVariablesFeature : 0;
        writeNum(data, features);
        writeNum(data, codeBlock->activationRegister().offset());
    } else
        ASSERT(codeBlock->codeType() == GlobalCode);

    // Save UnlinkedCodeBlock info
    writeNum(data, codeBlock->m_numCalleeRegisters);
    writeNum(data, codeBlock->m_numVars);
    writeNum(data, codeBlock->m_numCapturedVars);
    writeNum(data, codeBlock->numParameters());
    //writeBool(data, codeBlock->m_lastReturnFixed);
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
    if (codeBlock->getID()) { // Load FunctionExectable features
        ASSERT(codeBlock->codeType() == FunctionCode);
        UnlinkedFunctionExecutable *function = (static_cast<UnlinkedFunctionCodeBlock*>(codeBlock))->ownerExecutable();
        int features = readNum(p);
        ASSERT(function->isInStrictContext() == !!(features & StrictModeFeature));
        ASSERT(codeBlock->isStrictMode() == function->isInStrictContext());
        function->recordParse(features & AllFeatures, features & HasCapturedVariablesFeature);
        codeBlock->recordParse (features & AllFeatures, features & HasCapturedVariablesFeature, 0, 0, 0);
        codeBlock->setActivationRegister(VirtualRegister(readNum(p)));
    } else {
        ASSERT(codeBlock->codeType() == GlobalCode);
        ASSERT(m_programExecutable);
        m_programExecutable->recordParse(0, false, 0, 0, 0, 0);
    }

    // Load UnlinkedCodeBlock info
    codeBlock->m_numCalleeRegisters = readNum(p);
    codeBlock->m_numVars = readNum(p);
    codeBlock->m_numCapturedVars = readNum(p);
    codeBlock->setNumParameters(readNum(p));
    //codeBlock->m_lastReturnFixed = readBool(p);
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
        codeBlock->addJumpTarget(readNum(p));
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
        default:
            dataLogF("Not implemented\n");
            ASSERT_NOT_REACHED();
            CRASH();
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
        default:
            ASSERT_NOT_REACHED();
            CRASH();
            break;
        }
    } else
        v = JSValue::decode(readEncodedJSValue(p));
    return v;
}

void CodeBlockDatabase::writeConstants(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t num = codeBlock->numberOfConstantRegisters();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++)
        writeObject(data, codeBlock->getConstant(FirstConstantRegisterIndex + i), false);
}

void CodeBlockDatabase::readConstants(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfConstantRegisters() == 0);
    size_t num = readNum(p);
    for (size_t i = 0; i < num; i++)
        codeBlock->addConstant(readObject(p, false));
    ASSERT(codeBlock->numberOfConstantRegisters() == num);
}

void CodeBlockDatabase::writeConstantBuffers(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t elems, num = codeBlock->numberOfConstantBuffers();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        elems = codeBlock->getConstantBufferSize(i);
        writeNum(data, elems);
        for (size_t j = 0; j < elems; j++)
            writeObject(data, codeBlock->constantBuffer(i).at(j), true);
    }
}

void CodeBlockDatabase::readConstantBuffers(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfConstantBuffers() == 0);
    size_t elems, num = readNum(p);
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
    BytesData temp;
    bool global = (codeBlock->getID() == 0);
    ASSERT(codeBlock->codeType() == global ? GlobalCode : FunctionCode);
    size_t elems, num = codeBlock->m_symbols.size();
    ASSERT(num == codeBlock->m_regForSymbols.size());
    writeNum(data, num);
    if (!global) {
        ASSERT(codeBlock->symbolTable());
        int captureStart = codeBlock->symbolTable()->captureStart();
        int captureEnd = codeBlock->symbolTable()->captureEnd();
        writeNum(data, captureStart);
        writeNum(data, captureEnd);
    }
    else {
      SymbolTable *globalSymbol = m_scope->globalObject()->symbolTable();
      ConcurrentJITLocker locker(m_scope->globalObject()->symbolTable()->m_lock);
      writeNum(data, globalSymbol->size(locker));
      for (SymbolTable::Map::iterator iter = globalSymbol->begin(locker), end = globalSymbol->end(locker); iter != end; ++iter) {
	  writeInt64(data, iter->value.getBits());
	  iter->key.get()->toBytes(temp);
	  elems = temp.size();
	  writeNum(data, elems);
	  data.append(temp.data(), elems);
          temp.clear();
      }
    }
    for (size_t i = 0; i < num; i++) {
        writeInt64(data, codeBlock->m_regForSymbols[i]);
        codeBlock->m_symbols[i]->toBytes(temp);
        elems = temp.size();
        writeNum(data, elems);
        data.append(temp.data(), elems);
        temp.clear();
    }
}

void CodeBlockDatabase::readSymbolTable(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->m_regForSymbols.size() == 0);
    bool global = (codeBlock->getID() == 0);
    ASSERT(codeBlock->codeType() == global ? GlobalCode : FunctionCode);
    bool empty = !(codeBlock->symbolTable()->size());
    ASSERT(empty || codeBlock->codeType() == GlobalCode);
    ExecState* exec = m_scope->globalObject()->globalExec();

    size_t elems, num = readNum(p);

    if (!global) {
        codeBlock->symbolTable ()->setUsesNonStrictEval(codeBlock->usesEval() && !codeBlock->isStrictMode());
        codeBlock->symbolTable()->setCaptureStart(readNum(p));
        codeBlock->symbolTable()->setCaptureEnd(readNum(p));
    }
    else {
      size_t size = readNum(p);
      for (size_t i = 0; i < size; i++) {
	  SymbolTableEntry newEntry = SymbolTableEntry(SymbolTableEntry::Bits, readInt64(p));
	  //SymbolTableEntry newEntry = SymbolTableEntry(SymbolTableEntry::Bits, readInt64(p), m_scope->globalObject()->symbolTable()->size());
	  elems = readNum(p);
	  Identifier ident(exec, String(String::ByteStreamConstructor, *p, elems));
	  *p += elems;

	  ConcurrentJITLocker locker(m_scope->globalObject()->symbolTable()->m_lock);
	  SymbolTable::Map::AddResult result = m_scope->globalObject()->symbolTable()->add(locker, ident.impl(), newEntry);
	  //if (!result.isNewEntry)
	  //    result.iterator->value.prepareToWatch();
      }
   }

    for (size_t i = 0; i < num; i++) {
        codeBlock->m_regForSymbols.append(readInt64(p));
        elems = readNum(p);

        SymbolTableEntry newEntry = empty ? SymbolTableEntry(SymbolTableEntry::Bits, codeBlock->m_regForSymbols[i])
        : SymbolTableEntry(SymbolTableEntry::Bits, codeBlock->m_regForSymbols[i], codeBlock->symbolTable()->size());
        Identifier ident(exec, String(String::ByteStreamConstructor, *p, elems));
        *p += elems;

        SymbolTableEntry entry = m_scope->globalObject()->symbolTable()->get(ident.impl());

        if (!empty) {
            int index = !entry.isNull() ? entry.getIndex() : codeBlock->symbolTable()->size();
            m_newRegIndex.set(codeBlock->m_regForSymbols[i] >> 4, index);
        }

        {
            ConcurrentJITLocker locker(codeBlock->symbolTable()->m_lock);
            SymbolTable::Map::AddResult result = codeBlock->symbolTable()->add(locker, ident.impl(), newEntry);

            if (!result.isNewEntry)
                result.iterator->value.prepareToWatch();
        }
    }
}

void CodeBlockDatabase::writeIdentifiers(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    BytesData temp;
    size_t elems, num = codeBlock->numberOfIdentifiers();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        codeBlock->identifier(i).string().toBytes(temp);
        elems = temp.size();
        writeNum(data, elems);
        data.append(temp.data(), elems);
        temp.clear();
    }
}

void CodeBlockDatabase::readIdentifiers(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfIdentifiers() == 0);
    ExecState* exec = m_scope->globalObject()->globalExec();
    size_t elems, num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        elems = readNum(p);
        Identifier ident(exec, String(String::ByteStreamConstructor, *p, elems));
        *p += elems;
        codeBlock->addIdentifier(ident);
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

/*void CodeBlockDatabase::writeCharacterSwitchTables(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    size_t elems, num = codeBlock->numberOfCharacterSwitchJumpTables();
    writeNum(data, num);
    for (size_t i = 0; i < num; i++) {
        SimpleJumpTable& table = codeBlock->characterSwitchJumpTable(i);
        writeNum(data, table.min);
        elems = table.branchOffsets.size();
        writeNum(data, elems);
        for (size_t j = 0; j < elems; j++)
            writeNum(data, table.branchOffsets[j]);
    }
}

void CodeBlockDatabase::readCharacterSwitchTables(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfCharacterSwitchJumpTables() == 0);
    size_t elems, num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        codeBlock->addCharacterSwitchJumpTable();
        codeBlock->characterSwitchJumpTable(i).min = readNum(p);
        elems = readNum(p);
        for (size_t j = 0; j < elems; j++)
             codeBlock->characterSwitchJumpTable(i).branchOffsets.append(readNum(p));
    }
    ASSERT(codeBlock->numberOfCharacterSwitchJumpTables() == num);
}*/

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
    //writeCharacterSwitchTables(data, codeBlock);
    writeStringSwitchTables(data, codeBlock);
}

void CodeBlockDatabase::readSwitches(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    readImmediateSwitchTables(p, codeBlock);
    //readCharacterSwitchTables(p, codeBlock);
    readStringSwitchTables(p, codeBlock);
}

void CodeBlockDatabase::writeBytecode(BytesData& data, UnlinkedCodeBlock* codeBlock)
{
    writeNum(data, codeBlock->instructions().count());
    writeNum(data, codeBlock->instructions().byteSize());
    data.append(codeBlock->instructionsPointer()->data(), codeBlock->instructionsPointer()->byteSize());
/*    ExecState* exec = m_scopeChainNode->globalObject->globalExec();
    JSGlobalObject* globalObject = m_scopeChainNode->globalObject.get();
    size_t base = 0, num = codeBlock->instructionCount();
    Vector<Instruction> insns;
    insns.append(codeBlock->instructions().begin(), num);
    Instruction* instructions = insns.data();
    writeNum(data, num);
    while (base < num) {
        OpcodeID opcodeID = exec->interpreter()->getOpcodeID(instructions[base].u.opcode);
        size_t length = opcodeLengths[opcodeID];
        writeInsn(data, opcodeID);
        switch(opcodeID) {
            case op_put_global_var_check: {
                instructions[base + 3].u.jsCell.clear();
                break;
            }
            case op_get_global_var:
            case op_get_global_var_watchable:
            case op_resolve:
            case op_resolve_skip:
            case op_get_scoped_var:
            case op_resolve_base:
            case op_resolve_with_base:
            case op_resolve_with_this:
            case op_get_by_val:
            case op_get_argument_by_val:
            case op_get_by_id:
            case op_get_by_id_self:
            case op_get_by_id_proto:
            case op_get_by_id_chain:
            case op_get_by_id_getter_self:
            case op_get_by_id_getter_proto:
            case op_get_by_id_getter_chain:
            case op_get_by_id_custom_self:
            case op_get_by_id_custom_proto:
            case op_get_by_id_custom_chain:
            case op_get_by_id_generic:
            case op_get_array_length:
            case op_get_string_length:
            case op_resolve_global_dynamic:
            case op_resolve_global:
            case op_convert_this:
            case op_call_put_result: {
                instructions[base + length - 1].u.jsCell.clear();
                break;
            }
            case op_call:
            case op_call_eval:
            case op_construct: {
                instructions[base + 4].u.jsCell.clear();
                break;
            }
            default:
                break;
        }
        for (size_t i = 0; i < c_n_patch_info; ++i) {
            if (opcodeID == c_patch_infos[i].opcode) {
                WriteBarrier<Unknown>* registerPointer = instructions[base + c_patch_infos[i].patchInst].u.registerPointer;
                instructions[base + c_patch_infos[i].patchInst].u.jsCell.clear();
                instructions[base + c_patch_infos[i].patchInst].u.operand = globalObject->findRegisterIndex(registerPointer);
                break;
            }
        }
        for (size_t i = 1; i < length; ++i)
            writeInsn(data, instructions[base + i]);
        base += length;
    }
    insns.clear();*/
}

void CodeBlockDatabase::readBytecode(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    size_t insnCount = readNum(p);
    size_t byteSize = readNum(p);
    /*bool reconstruct = m_savingType == WithoutRun && codeBlock->isConstructor();
    ASSERT(!reconstruct || codeBlock->getID());*/
    ASSERT(NULL == codeBlock->instructionsPointer());
    Vector<unsigned char> data;
    data.append(*p, byteSize);
    *p += byteSize;
    codeBlock->setInstructions(std::make_unique<UnlinkedInstructionStream>(insnCount, data));
/*    ExecState* exec = m_scopeChainNode->globalObject->globalExec();
    JSGlobalObject* globalObject = m_scopeChainNode->globalObject.get();
    int thisIndex = codeBlock->thisRegister();
    ASSERT(m_savingType != NoType);
    size_t num, base;

#if !ASSERT_DISABLED
    unsigned patchedMovs = 0, patchedConv = 0;
#endif

    Vector<Instruction> instructions;
    num = readNum(p);
    for (size_t i = 0; i < num; i++)
        instructions.append(readInsn(p));

    base = 0;
    while (base < num) {*/
        /* Repatch each Opcode at a time */
/*        OpcodeID opcodeID = static_cast<OpcodeID>(instructions[base].u.operand);
        instructions[base].u.opcode = exec->interpreter()->getOpcode(opcodeID);
        size_t length = opcodeLengths[opcodeID];
        size_t lastIndex = length - 1;

        for (size_t i = 0; i < c_n_patch_info; ++i) {
            if (opcodeID == c_patch_infos[i].opcode) {
                int reg = instructions[base + c_patch_infos[i].patchInst].u.operand;
                if (reg && m_newRegIndex.contains(reg))
                    reg = m_newRegIndex.get(reg);
                instructions[base + c_patch_infos[i].patchInst].u.registerPointer = &globalObject->registerAt(reg);
                break;
            }
        }
        switch(opcodeID) {
            case op_put_global_var_check: {
                int operand = instructions[base + 4].u.operand;
                instructions[base + 3].u.pointer =
                    codeBlock->globalObject()->symbolTable().get(codeBlock->identifier(operand).impl()).addressOfIsWatched();
                break;
            }
            case op_get_global_var:
            case op_get_global_var_watchable:
            case op_resolve:
            case op_resolve_skip:
            case op_get_scoped_var:
            case op_resolve_base:
            case op_resolve_with_base:
            case op_resolve_with_this:
            case op_get_by_val:
            case op_get_argument_by_val:
            case op_get_by_id:
            case op_get_by_id_self:
            case op_get_by_id_proto:
            case op_get_by_id_chain:
            case op_get_by_id_getter_self:
            case op_get_by_id_getter_proto:
            case op_get_by_id_getter_chain:
            case op_get_by_id_custom_self:
            case op_get_by_id_custom_proto:
            case op_get_by_id_custom_chain:
            case op_get_by_id_generic:
            case op_get_array_length:
            case op_get_string_length:
            case op_call_put_result: {
                instructions[base + lastIndex].u.profile = codeBlock->addValueProfile(base);
                break;
            }
            case op_resolve_global_dynamic: {
                instructions[base + lastIndex].u.profile = codeBlock->addValueProfile(base);
#if ENABLE(JIT)
                codeBlock->addGlobalResolveInfo(base);
#endif
                codeBlock->addGlobalResolveInstruction(base);
                break;
            }
            case op_resolve_global: {
                instructions[base + lastIndex].u.profile = codeBlock->addValueProfile(base);
                int operand = instructions[base + 2].u.operand;
                SymbolTableEntry entry = codeBlock->globalObject()->symbolTable().get(codeBlock->identifier(operand).impl());
                if (!entry.isNull()) {
                    if (entry.couldBeWatched()) {
                        instructions[base + 3].u.operand = operand;
                        instructions[base].u.opcode = exec->interpreter()->getOpcode(op_get_global_var_watchable);
                    } else
                        instructions[base].u.opcode = exec->interpreter()->getOpcode(op_get_global_var);
                    instructions[base+2].u.registerPointer = &codeBlock->globalObject()->registerAt(entry.getIndex());
                } else {
#if ENABLE(JIT)
                    codeBlock->addGlobalResolveInfo(base);
#endif
                    codeBlock->addGlobalResolveInstruction(base);
		}
                break;
            }
            case op_call:
            case op_call_eval:
            case op_construct: {
#if ENABLE(LLINT)
                instructions[base + 4].u.callLinkInfo = codeBlock->addLLIntCallLinkInfo();
#else
#error LLINT required for AOTC
#endif
                break;
            }
            case op_ret: {
                ASSERT(instructions[base + 2].u.operand == 0);
                if (reconstruct) {
                    if (codeBlock->m_lastReturnFixed && base + length == num) {
#if !ASSERT_DISABLED
                        int index = instructions[base + 1].u.operand;
                        ASSERT(codeBlock->isConstantRegisterIndex(index));
                        ASSERT(codeBlock->constantRegister(index).get().isUndefined());
#endif
                        instructions[base + 1].u.operand = thisIndex;
                    } else if (instructions[base + 1].u.operand != thisIndex) {
                        instructions[base].u.opcode = exec->interpreter()->getOpcode(op_ret_object_or_this);
                        instructions[base + 2].u.operand = thisIndex;
                    }
                }
                break;
            }
            case op_convert_this: {
                if (reconstruct) {
                    instructions[base].u.opcode = exec->interpreter()->getOpcode(op_create_this);
                    instructions[base + 2].u.operand = 0;
#if !ASSERT_DISABLED
                    ASSERT(instructions[base + 1].u.operand == thisIndex);
                    patchedConv++;
#endif
                } else {
                    instructions[base + lastIndex].u.profile = codeBlock->addValueProfile(base);
                }
                break;
            }
            case op_mov: {
                if (reconstruct) {
                    if (instructions[base + 1].u.operand == thisIndex
                     && instructions[base + 2].u.operand == thisIndex) {
                        instructions[base].u.opcode = exec->interpreter()->getOpcode(op_create_this);
                        instructions[base + 2].u.operand = 0;
#if !ASSERT_DISABLED
                        patchedMovs++;
#endif
                    }
                }
                break;
            }
            default:
                break;
        }
        base += length;
    }
#if !ASSERT_DISABLED
    if (reconstruct)
        ASSERT(patchedMovs + patchedConv == 1);
#endif
    codeBlock->instructions() = RefCountedArray<Instruction>(instructions);*/
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

void CodeBlockDatabase::readExceptionHandlers(BytesPointer* p, UnlinkedCodeBlock* codeBlock)
{
    ASSERT(codeBlock->numberOfExceptionHandlers() == 0);
    size_t num = readNum(p);
    for (size_t i = 0; i < num; i++) {
        uint32_t start = readNum(p);
        uint32_t end = readNum(p);
        uint32_t target = readNum(p);
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
    //dataLogF("save block=%d offset=%d constructor=%d\n", blockID, blockID/2, blockID%2);
    ASSERT(m_blockIDs.size() == m_start.size());
    BytesData data;

    // Create data
    writeFunctions(data, codeBlock);
    writeCodeBlockInternals(data, codeBlock);
    writeJumpTargets(data, codeBlock);
    writeConstants(data, codeBlock);
    writeConstantBuffers(data, codeBlock);
    m_strings.clear();
    writeSymbolTable(data, codeBlock);
    writeIdentifiers(data, codeBlock);
    writeBytecode(data, codeBlock);
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

void CodeBlockDatabase::loadCodeBlock(UnlinkedCodeBlock* codeBlock, unsigned blockID)
{
    //dataLogF("load BlockID: %d\n", blockID);

    /*ExecState* exec = m_scopeChainNode->globalObject->globalExec();
    codeBlock->setThisRegister(CallFrame::thisArgumentOffset());
    codeBlock->setVM(&exec->vm());*/

    BytesData c_data;
    BytesData u_data;
    BytesPointer p = 0;
    int size = 0, origSize = 0, start;
    // Find info
    start = findStart(blockID, &size, &origSize);
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
    readJumpTargets(&p, codeBlock);
    m_strings.clear();
    readConstants(&p, codeBlock);
    readConstantBuffers(&p, codeBlock);
    readSymbolTable(&p, codeBlock);
    readIdentifiers(&p, codeBlock);
    readBytecode(&p, codeBlock);
    readSwitches(&p, codeBlock);
    readExceptionHandlers(&p, codeBlock);
    readRegExps(&p, codeBlock);

    // Check total bytes
    ASSERT(origSize == -1 ? p == c_data.data() + c_data.size() : p == u_data.data() + u_data.size());
    // Vectors are deallocated in their destructors
}

} // namespace JSC
