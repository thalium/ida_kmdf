// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Devices.Display.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Display {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Display {

struct WINRT_EBO DisplayMonitor :
    Windows::Devices::Display::IDisplayMonitor
{
    DisplayMonitor(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector();
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Display::DisplayMonitor> FromIdAsync(param::hstring const& deviceId);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Display::DisplayMonitor> FromInterfaceIdAsync(param::hstring const& deviceInterfaceId);
};

}
