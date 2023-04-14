// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Devices.Display.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Display {

struct WINRT_EBO IDisplayMonitor :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayMonitor>
{
    IDisplayMonitor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayMonitorStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayMonitorStatics>
{
    IDisplayMonitorStatics(std::nullptr_t = nullptr) noexcept {}
};

}
