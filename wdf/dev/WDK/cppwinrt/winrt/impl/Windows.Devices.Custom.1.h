// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Devices.Custom.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Custom {

struct WINRT_EBO ICustomDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICustomDevice>
{
    ICustomDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICustomDeviceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICustomDeviceStatics>
{
    ICustomDeviceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IIOControlCode :
    Windows::Foundation::IInspectable,
    impl::consume_t<IIOControlCode>
{
    IIOControlCode(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IIOControlCodeFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IIOControlCodeFactory>
{
    IIOControlCodeFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownDeviceTypesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownDeviceTypesStatics>
{
    IKnownDeviceTypesStatics(std::nullptr_t = nullptr) noexcept {}
};

}
