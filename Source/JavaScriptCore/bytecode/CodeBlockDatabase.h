
#ifndef CodeBlockDatabase_h
#define CodeBlockDatabase_h

#include "Opcode.h"
#include "JSCJSValue.h"
#include <runtime/CodeSpecializationKind.h>
#include <wtf/PassOwnPtr.h>
#include <wtf/Platform.h>
#include <wtf/RefCounted.h>
#include <wtf/Vector.h>
#include <wtf/text/WTFString.h>

namespace JSC {

    class ExecState;
    class FunctionExecutable;
    class FunctionParameters;
    class FunctionCodeBlock;
    class HandlerInfo;
    class Identifier;
    class JSScope;
    class ProgramCodeBlock;
    class ProgramExecutable;
    class ScopeChainNode;
    class SimpleJumpTable;
    class SourceProvider;
    class StringJumpTable;
    class StringOffsetTable;
    class UnlinkedCodeBlock;
    class UnlinkedFunctionCodeBlock;
    class UnlinkedFunctionExecutable;
    class UnlinkedProgramCodeBlock;

    class CodeBlockDatabase : public RefCounted<CodeBlockDatabase> {
    public:
        static PassRefPtr<CodeBlockDatabase> create(const String& fileName)
        {
            return adoptRef(new CodeBlockDatabase(fileName));
        }

        void setProvider(PassRefPtr<SourceProvider> provider)
        {
            ASSERT(!m_provider || m_provider == provider);
            m_provider = provider;
        }

        void open(bool initDb);
        ~CodeBlockDatabase();

        void saveProgramCodeBlock(JSScope*, UnlinkedProgramCodeBlock*, ProgramExecutable*);
        UnlinkedProgramCodeBlock* loadProgramCodeBlock(JSScope*, ProgramExecutable*);
        void saveFunctionCodeBlock(JSScope*, UnlinkedCodeBlock*);
        UnlinkedFunctionCodeBlock* loadFunctionCodeBlock(JSScope*, FunctionExecutable*, CodeSpecializationKind);

    private:
        typedef Vector<char> BytesData;
        typedef const char* BytesPointer;

        CodeBlockDatabase(const String&);
        CodeBlockDatabase(const String&, PassRefPtr<SourceProvider>);

        void createSearchTable();
        void extractSearchTable();
        int findStart(int, int*, int*);

        void saveCodeBlock(UnlinkedCodeBlock*);
        bool loadCodeBlock(UnlinkedCodeBlock*, unsigned);

        void writeCodeBlockInternals(BytesData&, UnlinkedCodeBlock*);
        void readCodeBlockInternals(BytesPointer*, UnlinkedCodeBlock*);
        void writeJumpTargets(BytesData&, UnlinkedCodeBlock*);
        void readJumpTargets(BytesPointer*, UnlinkedCodeBlock*);
        void writeConstants(BytesData&, UnlinkedCodeBlock*);
        void readConstants(BytesPointer*, UnlinkedCodeBlock*);
        void writeSymbolTable(BytesData&, UnlinkedCodeBlock*);
        void readSymbolTable(BytesPointer*, UnlinkedCodeBlock*);
        void writeIdentifiers(BytesData&, UnlinkedCodeBlock*);
        void readIdentifiers(BytesPointer*, UnlinkedCodeBlock*);
        void writeBytecode(BytesData&, UnlinkedCodeBlock*);
        void readBytecode(BytesPointer*, UnlinkedCodeBlock*);
        void writeExceptionHandlers( BytesData&, UnlinkedCodeBlock*);
        void readExceptionHandlers(BytesPointer*, UnlinkedCodeBlock*);
        unsigned constructorShift(unsigned, UnlinkedCodeBlock*);
        void writeRegExps(BytesData&, UnlinkedCodeBlock*);
        void readRegExps(BytesPointer*, UnlinkedCodeBlock*);

        void writeImmediateSwitchTables(BytesData&, UnlinkedCodeBlock*);
        void readImmediateSwitchTables(BytesPointer*, UnlinkedCodeBlock*);
        void writeStringSwitchTables(BytesData&, UnlinkedCodeBlock*);
        void readStringSwitchTables(BytesPointer*, UnlinkedCodeBlock*);
        void writeSwitches(BytesData&, UnlinkedCodeBlock*);
        void readSwitches(BytesPointer*, UnlinkedCodeBlock*);

        void writeFunctions(BytesData&, UnlinkedCodeBlock*);
        void readFunctions(BytesPointer*, UnlinkedCodeBlock*);
        void writeFunction(BytesData&, UnlinkedFunctionExecutable*);
        UnlinkedFunctionExecutable* readFunction(BytesPointer*, UnlinkedCodeBlock*);

        void writeNum(BytesData&, int);
        int readNum(BytesPointer*);
        void writeInt64(BytesData&, int64_t);
        int64_t readInt64(BytesPointer*);
        void writeBool(BytesData&, bool);
        bool readBool(BytesPointer*);
        void writeEncodedJSValue(BytesData&, EncodedJSValue);
        EncodedJSValue readEncodedJSValue(BytesPointer*);
        void writeObject(BytesData&, JSValue, bool);
        JSValue readObject(BytesPointer*, bool);

        JSScope* m_scope;
        ProgramExecutable* m_programExecutable;

        String m_file_name;
        FILE* m_file;
        bool m_fileWrite;
        RefPtr<SourceProvider> m_provider;

        enum SavingType { NoType, WithoutRun, WithRun } m_savingType;

        Vector<JSValue> m_strings;
        int m_constructorShift;

        Vector<int> m_blockIDs;
        Vector<int> m_start;
        Vector<int> m_origSize;
        BytesData m_data;
    };
} // namespace JSC

#endif // CodeBlockDatabase_h
