// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.UI.Input.Inking.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview {

struct WINRT_EBO IPalmRejectionDelayZonePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPalmRejectionDelayZonePreview>
{
    IPalmRejectionDelayZonePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPalmRejectionDelayZonePreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPalmRejectionDelayZonePreviewStatics>
{
    IPalmRejectionDelayZonePreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

}
