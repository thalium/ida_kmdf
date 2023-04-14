// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Devices.Portable.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Portable {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Portable {

struct ServiceDevice
{
    ServiceDevice() = delete;
    static hstring GetDeviceSelector(Windows::Devices::Portable::ServiceDeviceType const& serviceType);
    static hstring GetDeviceSelectorFromServiceId(winrt::guid const& serviceId);
};

struct StorageDevice
{
    StorageDevice() = delete;
    static Windows::Storage::StorageFolder FromId(param::hstring const& deviceId);
    static hstring GetDeviceSelector();
};

}
