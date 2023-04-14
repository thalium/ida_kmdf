// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.UI.Composition.Desktop.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop {

struct WINRT_EBO IDesktopWindowTarget :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesktopWindowTarget>
{
    IDesktopWindowTarget(std::nullptr_t = nullptr) noexcept {}
};

}
