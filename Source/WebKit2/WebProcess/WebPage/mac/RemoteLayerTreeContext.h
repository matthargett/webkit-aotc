/*
 * Copyright (C) 2012 Apple Inc. All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RemoteLayerTreeContext_h
#define RemoteLayerTreeContext_h

#include "LayerTreeContext.h"
#include "RemoteLayerTreeTransaction.h"
#include "WebPage.h"
#include <WebCore/GraphicsLayerFactory.h>
#include <WebCore/PlatformCALayer.h>
#include <wtf/Vector.h>

namespace WebKit {

class PlatformCALayerRemote;
class WebPage;

// FIXME: This class doesn't do much now. Roll into RemoteLayerTreeDrawingArea?
class RemoteLayerTreeContext : public WebCore::GraphicsLayerFactory {
public:
    explicit RemoteLayerTreeContext(WebPage*);
    ~RemoteLayerTreeContext();

    void layerWasCreated(PlatformCALayerRemote*, WebCore::PlatformCALayer::LayerType);
    void layerWillBeDestroyed(PlatformCALayerRemote*);

    void outOfTreeLayerWasAdded(WebCore::GraphicsLayer*);
    void outOfTreeLayerWillBeRemoved(WebCore::GraphicsLayer*);

    LayerHostingMode layerHostingMode() const { return m_webPage->layerHostingMode(); }

    void flushOutOfTreeLayers();
    void buildTransaction(RemoteLayerTreeTransaction&, WebCore::PlatformCALayer& rootLayer);

    // From the UI process
    void animationDidStart(WebCore::GraphicsLayer::PlatformLayerID, double startTime);

    void willStartAnimationOnLayer(PlatformCALayerRemote*);

private:
    // WebCore::GraphicsLayerFactory
    virtual std::unique_ptr<WebCore::GraphicsLayer> createGraphicsLayer(WebCore::GraphicsLayerClient*) override;

    WebPage* m_webPage;

    RefPtr<PlatformCALayerRemote> m_rootLayer;
    Vector<WebCore::GraphicsLayer*> m_outOfTreeLayers;

    Vector<RemoteLayerTreeTransaction::LayerCreationProperties> m_createdLayers;
    Vector<WebCore::GraphicsLayer::PlatformLayerID> m_destroyedLayers;
    
    HashMap<WebCore::GraphicsLayer::PlatformLayerID, PlatformCALayerRemote*> m_layersAwaitingAnimationStart;
};

} // namespace WebKit

#endif // RemoteLayerTreeContext_h
