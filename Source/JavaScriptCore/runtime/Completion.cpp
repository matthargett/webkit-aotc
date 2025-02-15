/*
 *  Copyright (C) 1999-2001 Harri Porten (porten@kde.org)
 *  Copyright (C) 2001 Peter Kelly (pmk@post.com)
 *  Copyright (C) 2003, 2007, 2013 Apple Inc.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public License
 *  along with this library; see the file COPYING.LIB.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA 02110-1301, USA.
 *
 */

#include "config.h"
#include "Completion.h"

#include "CallFrame.h"
#include "CodeProfiling.h"
#include "Debugger.h"
#include "Interpreter.h"
#include "JSGlobalObject.h"
#include "JSLock.h"
#include "JSCInlines.h"
#include "Parser.h"
#include <wtf/WTFThreadData.h>

namespace JSC {

bool checkSyntax(ExecState* exec, const SourceCode& source, JSValue* returnedException)
{
    JSLockHolder lock(exec);
    RELEASE_ASSERT(exec->vm().atomicStringTable() == wtfThreadData().atomicStringTable());

    ProgramExecutable* program = ProgramExecutable::create(exec, source);
    JSObject* error = program->checkSyntax(exec);
    if (error) {
        if (returnedException)
            *returnedException = error;
        return false;
    }

    return true;
}
    
bool checkSyntax(VM& vm, const SourceCode& source, ParserError& error)
{
    JSLockHolder lock(vm);
    RELEASE_ASSERT(vm.atomicStringTable() == wtfThreadData().atomicStringTable());
    RefPtr<ProgramNode> programNode = parse<ProgramNode>(&vm, source, 0, Identifier(), JSParseNormal, JSParseProgramCode, error);
    return programNode;
}

bool dumpBytecodeFull(ExecState* exec, const SourceCode& source, JSValue* returnedException)
{
    ProgramExecutable* program = ProgramExecutable::create(exec, source);
    JSScope *scope = exec->scope();
    VM& vm = *scope->vm();
    JSObject* error = program->initializeGlobalProperties(vm, exec, scope);
    if (error) {
        if (returnedException) {
            *returnedException = exec->vm().throwException(exec, error);
            ASSERT(*returnedException);
        }
        ASSERT(exec->hadException());
        exec->clearException();
        return false;
    }
    ASSERT(!exec->hadException());
    return true;
}

JSValue evaluate(ExecState* exec, const SourceCode& source, JSValue thisValue, JSValue* returnedException)
{
    JSLockHolder lock(exec);
    RELEASE_ASSERT(exec->vm().atomicStringTable() == wtfThreadData().atomicStringTable());
    RELEASE_ASSERT(!exec->vm().isCollectorBusy());

    CodeProfiling profile(source);

    ProgramExecutable* program = ProgramExecutable::create(exec, source);
    if (!program) {
        if (returnedException)
            *returnedException = exec->vm().exception();

        exec->vm().clearException();
        return jsUndefined();
    }

    if (!thisValue || thisValue.isUndefinedOrNull())
        thisValue = exec->vmEntryGlobalObject();
    JSObject* thisObj = jsCast<JSObject*>(thisValue.toThis(exec, NotStrictMode));
    JSValue result = exec->interpreter()->execute(program, exec, thisObj);

    if (exec->hadException()) {
        if (returnedException)
            *returnedException = exec->exception();

        exec->clearException();
        return jsUndefined();
    }

    RELEASE_ASSERT(result);
    return result;
}

} // namespace JSC
