/*
    This file is part of the WebKit open source project.
    This file has been generated by generate-bindings.pl. DO NOT MODIFY!

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#ifndef JSTestCustomNamedGetter_h
#define JSTestCustomNamedGetter_h

#include "JSDOMBinding.h"
#include "TestCustomNamedGetter.h"
#include <runtime/JSGlobalObject.h>
#include <runtime/JSObject.h>
#include <runtime/ObjectPrototype.h>

namespace WebCore {

class JSTestCustomNamedGetter : public JSDOMWrapper {
public:
    typedef JSDOMWrapper Base;
    static JSTestCustomNamedGetter* create(JSC::Structure* structure, JSDOMGlobalObject* globalObject, PassRefPtr<TestCustomNamedGetter> impl)
    {
        JSTestCustomNamedGetter* ptr = new (NotNull, JSC::allocateCell<JSTestCustomNamedGetter>(globalObject->vm().heap)) JSTestCustomNamedGetter(structure, globalObject, impl);
        ptr->finishCreation(globalObject->vm());
        return ptr;
    }

    static JSC::JSObject* createPrototype(JSC::VM&, JSC::JSGlobalObject*);
    static bool getOwnPropertySlot(JSC::JSObject*, JSC::ExecState*, JSC::PropertyName, JSC::PropertySlot&);
    static bool getOwnPropertySlotByIndex(JSC::JSObject*, JSC::ExecState*, unsigned propertyName, JSC::PropertySlot&);
    static void destroy(JSC::JSCell*);
    ~JSTestCustomNamedGetter();
    DECLARE_INFO;

    static JSC::Structure* createStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::JSValue prototype)
    {
        return JSC::Structure::create(vm, globalObject, prototype, JSC::TypeInfo(JSC::ObjectType, StructureFlags), info());
    }

    static JSC::JSValue getConstructor(JSC::VM&, JSC::JSGlobalObject*);
    TestCustomNamedGetter& impl() const { return *m_impl; }
    void releaseImpl() { m_impl->deref(); m_impl = 0; }

    void releaseImplIfNotNull()
    {
        if (m_impl) {
            m_impl->deref();
            m_impl = 0;
        }
    }

private:
    TestCustomNamedGetter* m_impl;
protected:
    JSTestCustomNamedGetter(JSC::Structure*, JSDOMGlobalObject*, PassRefPtr<TestCustomNamedGetter>);

    void finishCreation(JSC::VM& vm)
    {
        Base::finishCreation(vm);
        ASSERT(inherits(info()));
    }

    static const unsigned StructureFlags = JSC::HasImpureGetOwnPropertySlot | JSC::InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero | JSC::OverridesGetOwnPropertySlot | Base::StructureFlags;
private:
    static bool canGetItemsForName(JSC::ExecState*, TestCustomNamedGetter*, JSC::PropertyName);
    static JSC::EncodedJSValue nameGetter(JSC::ExecState*, JSC::JSObject*, JSC::EncodedJSValue, JSC::PropertyName);
};

class JSTestCustomNamedGetterOwner : public JSC::WeakHandleOwner {
public:
    virtual bool isReachableFromOpaqueRoots(JSC::Handle<JSC::Unknown>, void* context, JSC::SlotVisitor&);
    virtual void finalize(JSC::Handle<JSC::Unknown>, void* context);
};

inline JSC::WeakHandleOwner* wrapperOwner(DOMWrapperWorld&, TestCustomNamedGetter*)
{
    DEPRECATED_DEFINE_STATIC_LOCAL(JSTestCustomNamedGetterOwner, jsTestCustomNamedGetterOwner, ());
    return &jsTestCustomNamedGetterOwner;
}

inline void* wrapperContext(DOMWrapperWorld& world, TestCustomNamedGetter*)
{
    return &world;
}

JSC::JSValue toJS(JSC::ExecState*, JSDOMGlobalObject*, TestCustomNamedGetter*);
TestCustomNamedGetter* toTestCustomNamedGetter(JSC::JSValue);

class JSTestCustomNamedGetterPrototype : public JSC::JSNonFinalObject {
public:
    typedef JSC::JSNonFinalObject Base;
    static JSC::JSObject* self(JSC::VM&, JSC::JSGlobalObject*);
    static JSTestCustomNamedGetterPrototype* create(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::Structure* structure)
    {
        JSTestCustomNamedGetterPrototype* ptr = new (NotNull, JSC::allocateCell<JSTestCustomNamedGetterPrototype>(vm.heap)) JSTestCustomNamedGetterPrototype(vm, globalObject, structure);
        ptr->finishCreation(vm);
        return ptr;
    }

    DECLARE_INFO;
    static bool getOwnPropertySlot(JSC::JSObject*, JSC::ExecState*, JSC::PropertyName, JSC::PropertySlot&);
    static JSC::Structure* createStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::JSValue prototype)
    {
        return JSC::Structure::create(vm, globalObject, prototype, JSC::TypeInfo(JSC::ObjectType, StructureFlags), info());
    }

private:
    JSTestCustomNamedGetterPrototype(JSC::VM& vm, JSC::JSGlobalObject*, JSC::Structure* structure) : JSC::JSNonFinalObject(vm, structure) { }
protected:
    static const unsigned StructureFlags = JSC::OverridesGetOwnPropertySlot | Base::StructureFlags;
};

class JSTestCustomNamedGetterConstructor : public DOMConstructorObject {
private:
    JSTestCustomNamedGetterConstructor(JSC::Structure*, JSDOMGlobalObject*);
    void finishCreation(JSC::VM&, JSDOMGlobalObject*);

public:
    typedef DOMConstructorObject Base;
    static JSTestCustomNamedGetterConstructor* create(JSC::VM& vm, JSC::Structure* structure, JSDOMGlobalObject* globalObject)
    {
        JSTestCustomNamedGetterConstructor* ptr = new (NotNull, JSC::allocateCell<JSTestCustomNamedGetterConstructor>(vm.heap)) JSTestCustomNamedGetterConstructor(structure, globalObject);
        ptr->finishCreation(vm, globalObject);
        return ptr;
    }

    static bool getOwnPropertySlot(JSC::JSObject*, JSC::ExecState*, JSC::PropertyName, JSC::PropertySlot&);
    DECLARE_INFO;
    static JSC::Structure* createStructure(JSC::VM& vm, JSC::JSGlobalObject* globalObject, JSC::JSValue prototype)
    {
        return JSC::Structure::create(vm, globalObject, prototype, JSC::TypeInfo(JSC::ObjectType, StructureFlags), info());
    }
protected:
    static const unsigned StructureFlags = JSC::OverridesGetOwnPropertySlot | JSC::ImplementsHasInstance | DOMConstructorObject::StructureFlags;
};

// Functions

JSC::EncodedJSValue JSC_HOST_CALL jsTestCustomNamedGetterPrototypeFunctionAnotherFunction(JSC::ExecState*);
// Attributes

JSC::EncodedJSValue jsTestCustomNamedGetterConstructor(JSC::ExecState*, JSC::JSObject*, JSC::EncodedJSValue, JSC::PropertyName);

} // namespace WebCore

#endif
