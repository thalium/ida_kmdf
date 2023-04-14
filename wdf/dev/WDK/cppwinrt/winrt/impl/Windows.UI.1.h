// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.0.h"

WINRT_EXPORT namespace winrt::Windows::UI {

struct WINRT_EBO IColorHelper :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorHelper>
{
    IColorHelper(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorHelperStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorHelperStatics>
{
    IColorHelperStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorHelperStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorHelperStatics2>
{
    IColorHelperStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColors :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColors>
{
    IColors(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorsStatics>
{
    IColorsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUIContentRoot :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUIContentRoot>
{
    IUIContentRoot(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUIContext :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUIContext>
{
    IUIContext(std::nullptr_t = nullptr) noexcept {}
};

}
