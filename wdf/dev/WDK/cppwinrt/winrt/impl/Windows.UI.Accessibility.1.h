// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Accessibility.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Accessibility {

struct WINRT_EBO IScreenReaderPositionChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScreenReaderPositionChangedEventArgs>
{
    IScreenReaderPositionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScreenReaderService :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScreenReaderService>
{
    IScreenReaderService(std::nullptr_t = nullptr) noexcept {}
};

}
