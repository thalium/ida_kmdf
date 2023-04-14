// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Activation.1.h"
#include "winrt/impl/Windows.Perception.Spatial.1.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.Holographic.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic {

struct HolographicApplicationPreview
{
    HolographicApplicationPreview() = delete;
    static bool IsCurrentViewPresentedOnHolographicDisplay();
    static bool IsHolographicActivation(Windows::ApplicationModel::Activation::IActivatedEventArgs const& activatedEventArgs);
};

struct WINRT_EBO HolographicKeyboardPlacementOverridePreview :
    Windows::ApplicationModel::Preview::Holographic::IHolographicKeyboardPlacementOverridePreview
{
    HolographicKeyboardPlacementOverridePreview(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::Preview::Holographic::HolographicKeyboardPlacementOverridePreview GetForCurrentView();
};

}
