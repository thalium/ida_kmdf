// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Custom.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Custom {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Custom {

struct WINRT_EBO CustomDevice :
    Windows::Devices::Custom::ICustomDevice
{
    CustomDevice(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector(winrt::guid const& classGuid);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice> FromIdAsync(param::hstring const& deviceId, Windows::Devices::Custom::DeviceAccessMode const& desiredAccess, Windows::Devices::Custom::DeviceSharingMode const& sharingMode);
};

struct WINRT_EBO IOControlCode :
    Windows::Devices::Custom::IIOControlCode
{
    IOControlCode(std::nullptr_t) noexcept {}
    IOControlCode(uint16_t deviceType, uint16_t function, Windows::Devices::Custom::IOControlAccessMode const& accessMode, Windows::Devices::Custom::IOControlBufferingMethod const& bufferingMethod);
};

struct KnownDeviceTypes
{
    KnownDeviceTypes() = delete;
    static uint16_t Unknown();
};

}
