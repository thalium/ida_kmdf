// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Display.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Display {

struct WINRT_EBO IDisplayRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayRequest>
{
    IDisplayRequest(std::nullptr_t = nullptr) noexcept {}
};

}
