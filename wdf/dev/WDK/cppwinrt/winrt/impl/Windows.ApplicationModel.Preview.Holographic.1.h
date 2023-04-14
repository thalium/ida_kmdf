// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Activation.0.h"
#include "winrt/impl/Windows.Perception.Spatial.0.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.Holographic.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::Holographic {

struct WINRT_EBO IHolographicApplicationPreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHolographicApplicationPreviewStatics>
{
    IHolographicApplicationPreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHolographicKeyboardPlacementOverridePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHolographicKeyboardPlacementOverridePreview>
{
    IHolographicKeyboardPlacementOverridePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHolographicKeyboardPlacementOverridePreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHolographicKeyboardPlacementOverridePreviewStatics>
{
    IHolographicKeyboardPlacementOverridePreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

}
