// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Background.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Background {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Background {

struct WINRT_EBO DeviceServicingDetails :
    Windows::Devices::Background::IDeviceServicingDetails
{
    DeviceServicingDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DeviceUseDetails :
    Windows::Devices::Background::IDeviceUseDetails
{
    DeviceUseDetails(std::nullptr_t) noexcept {}
};

}
