// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Accessibility.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Accessibility {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Accessibility {

struct WINRT_EBO ScreenReaderPositionChangedEventArgs :
    Windows::UI::Accessibility::IScreenReaderPositionChangedEventArgs
{
    ScreenReaderPositionChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ScreenReaderService :
    Windows::UI::Accessibility::IScreenReaderService
{
    ScreenReaderService(std::nullptr_t) noexcept {}
    ScreenReaderService();
};

}
