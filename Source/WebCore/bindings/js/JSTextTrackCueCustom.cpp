/*
 * Copyright (C) 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
 */

#include "config.h"

#if ENABLE(VIDEO_TRACK)

#include "JSDataCue.h"
#include "JSTextTrackCue.h"
#include "JSTrackCustom.h"
#include "JSVTTCue.h"
#include "TextTrack.h"

using namespace JSC;

namespace WebCore {

bool JSTextTrackCueOwner::isReachableFromOpaqueRoots(JSC::Handle<JSC::Unknown> handle, void*, SlotVisitor& visitor)
{
    JSTextTrackCue* jsTextTrackCue = jsCast<JSTextTrackCue*>(handle.slot()->asCell());
    TextTrackCue& textTrackCue = jsTextTrackCue->impl();

    // If the cue is firing event listeners, its wrapper is reachable because
    // the wrapper is responsible for marking those event listeners.
    if (textTrackCue.isFiringEventListeners())
        return true;

    // If the cue has no event listeners and has no custom properties, it is not reachable.
    if (!textTrackCue.hasEventListeners() && !jsTextTrackCue->hasCustomProperties())
        return false;

    // If the cue is not associated with a track, it is not reachable.
    if (!textTrackCue.track())
        return false;

    return visitor.containsOpaqueRoot(root(textTrackCue.track()));
}

JSValue toJS(ExecState*, JSDOMGlobalObject* globalObject, TextTrackCue* cue)
{
    if (!cue)
        return jsNull();

    JSObject* wrapper = getCachedWrapper(globalObject->world(), cue);

    if (wrapper)
        return wrapper;

    // This switch will make more sense once we support DataCue
    switch (cue->cueType()) {
    case TextTrackCue::Data:
        return CREATE_DOM_WRAPPER(globalObject, DataCue, cue);
    case TextTrackCue::WebVTT:
    case TextTrackCue::Generic:
        return CREATE_DOM_WRAPPER(globalObject, VTTCue, cue);
    default:
        ASSERT_NOT_REACHED();
        return jsNull();
    }
}

void JSTextTrackCue::visitChildren(JSCell* cell, SlotVisitor& visitor)
{
    JSTextTrackCue* jsTextTrackCue = jsCast<JSTextTrackCue*>(cell);
    ASSERT_GC_OBJECT_INHERITS(jsTextTrackCue, info());
    COMPILE_ASSERT(StructureFlags & OverridesVisitChildren, OverridesVisitChildrenWithoutSettingFlag);
    ASSERT(jsTextTrackCue->structure()->typeInfo().overridesVisitChildren());
    Base::visitChildren(jsTextTrackCue, visitor);

    // Mark the cue's track root if it has one.
    TextTrackCue& textTrackCue = jsTextTrackCue->impl();
    if (TextTrack* textTrack = textTrackCue.track())
        visitor.addOpaqueRoot(root(textTrack));
    
    textTrackCue.visitJSEventListeners(visitor);
}

} // namespace WebCore

#endif
