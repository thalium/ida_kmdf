// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Display.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Display {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Display {

struct WINRT_EBO DisplayRequest :
    Windows::System::Display::IDisplayRequest
{
    DisplayRequest(std::nullptr_t) noexcept {}
    DisplayRequest();
};

}
