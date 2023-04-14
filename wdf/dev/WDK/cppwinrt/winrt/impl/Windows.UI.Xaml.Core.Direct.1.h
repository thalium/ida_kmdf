// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.Xaml.0.h"
#include "winrt/impl/Windows.UI.Xaml.Media.0.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.0.h"
#include "winrt/impl/Windows.UI.Xaml.Core.Direct.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Core::Direct {

struct WINRT_EBO IXamlDirect :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlDirect>
{
    IXamlDirect(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlDirectObject :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlDirectObject>
{
    IXamlDirectObject(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlDirectStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlDirectStatics>
{
    IXamlDirectStatics(std::nullptr_t = nullptr) noexcept {}
};

}
