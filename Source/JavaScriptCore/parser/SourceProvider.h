/*
 * Copyright (C) 2008, 2009, 2012, 2013 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SourceProvider_h
#define SourceProvider_h

#include "CodeBlockDatabase.h"
#include <wtf/PassOwnPtr.h>
#include <wtf/RefCounted.h>
#include <wtf/text/TextPosition.h>
#include <wtf/text/WTFString.h>

namespace JSC {

    class SourceProvider : public RefCounted<SourceProvider> {
    public:
        static const intptr_t nullID = 1;
        
        JS_EXPORT_PRIVATE SourceProvider(const String& url, const TextPosition& startPosition);

        JS_EXPORT_PRIVATE virtual ~SourceProvider();

        virtual const String& source() const = 0;
        virtual bool isDatabaseProvider() const = 0;
        virtual CodeBlockDatabase* codeBlockDatabaseToLoad() const = 0;
        String getRange(int start, int end) const
        {
            return source().substringSharingImpl(start, end - start);
        }

        const String& url() { return m_url; }
        TextPosition startPosition() const { return m_startPosition; }
        intptr_t asID()
        {
            ASSERT(this);
            if (!this) // Be defensive in release mode.
                return nullID;
            if (!m_id)
                getID();
            return m_id;
        }

        bool writingToDatabase() { return m_savingDatabaseCreated; }

        CodeBlockDatabase* codeBlockDatabaseToSave() const
        {
            ASSERT(m_savingDatabaseCreated && !!m_savingDatabase);
            return m_savingDatabase.get();
        }

        void connectCodeBlockDatabaseToSave(String name)
        {
            m_savingDatabase = CodeBlockDatabase::create(name);
            m_savingDatabaseCreated = true;
        }

        bool isValid() const { return m_validated; }
        void setValid() { m_validated = true; }

    private:

        JS_EXPORT_PRIVATE void getID();
        Vector<size_t>& lineStarts();

        String m_url;
        TextPosition m_startPosition;
        RefPtr<CodeBlockDatabase> m_savingDatabase;
        bool m_savingDatabaseCreated : 1;
        bool m_validated : 1;
        uintptr_t m_id : sizeof(uintptr_t) * 8 - 2;
    };

    class StringSourceProvider : public SourceProvider {
    public:
        static PassRefPtr<StringSourceProvider> create(const String& source, const String& url, const TextPosition& startPosition = TextPosition::minimumPosition())
        {
            return adoptRef(new StringSourceProvider(source, url, startPosition));
        }

        virtual const String& source() const override
        {
            return m_source;
        }

        virtual bool isDatabaseProvider() const override { return false; }
        virtual CodeBlockDatabase* codeBlockDatabaseToLoad() const override { return NULL; };
    private:
        StringSourceProvider(const String& source, const String& url, const TextPosition& startPosition)
            : SourceProvider(url, startPosition)
            , m_source(source)
        {
        }

        String m_source;
    };
    
    class DatabaseSourceProvider : public SourceProvider {
    public:
        static PassRefPtr<DatabaseSourceProvider> create(const String& databaseFileName, const String& url, const TextPosition& startPosition = TextPosition::minimumPosition())
        {
            return adoptRef(new DatabaseSourceProvider(databaseFileName, url, startPosition));
        }

        virtual const String& source() const override
        {
            ASSERT_NOT_REACHED();
            return m_source;
        }
        //virtual String getRange(int start, int end) const override { ASSERT_NOT_REACHED(); return String(); }
        //const StringImpl* data() const { ASSERT_NOT_REACHED(); return 0; }
        //int length() const { ASSERT_NOT_REACHED(); return 0; }

        virtual bool isDatabaseProvider() const override { return true; }
        virtual CodeBlockDatabase* codeBlockDatabaseToLoad() const override { return m_loadingDatabase.get(); }
    private:
        DatabaseSourceProvider(const String& databaseFileName, const String& url, const TextPosition& startPosition)
            : SourceProvider(url, startPosition)
            , m_source("{ /* Bad Beef */ }")
            , m_loadingDatabase(CodeBlockDatabase::create(databaseFileName))
        {
        }

        String m_source;
        RefPtr<CodeBlockDatabase> m_loadingDatabase;
    };
} // namespace JSC

#endif // SourceProvider_h
