// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Input.Inking.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview {

struct WINRT_EBO PalmRejectionDelayZonePreview :
    Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview,
    impl::require<PalmRejectionDelayZonePreview, Windows::Foundation::IClosable>
{
    PalmRejectionDelayZonePreview(std::nullptr_t) noexcept {}
    static Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect);
    static Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect, Windows::UI::Composition::Visual const& viewportVisual, Windows::Foundation::Rect const& viewportRect);
};

}
