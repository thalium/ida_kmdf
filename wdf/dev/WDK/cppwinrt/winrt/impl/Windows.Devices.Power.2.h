// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Power.1.h"
#include "winrt/impl/Windows.Devices.Power.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Power {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Power {

struct WINRT_EBO Battery :
    Windows::Devices::Power::IBattery
{
    Battery(std::nullptr_t) noexcept {}
    static Windows::Devices::Power::Battery AggregateBattery();
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery> FromIdAsync(param::hstring const& deviceId);
    static hstring GetDeviceSelector();
};

struct WINRT_EBO BatteryReport :
    Windows::Devices::Power::IBatteryReport
{
    BatteryReport(std::nullptr_t) noexcept {}
};

}
