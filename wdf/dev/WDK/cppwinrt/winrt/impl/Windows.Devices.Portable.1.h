// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Devices.Portable.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Portable {

struct WINRT_EBO IServiceDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IServiceDeviceStatics>
{
    IServiceDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorageDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorageDeviceStatics>
{
    IStorageDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

}
