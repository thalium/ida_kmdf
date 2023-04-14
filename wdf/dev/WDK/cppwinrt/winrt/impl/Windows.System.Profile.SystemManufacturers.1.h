// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.System.Profile.SystemManufacturers.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers {

struct WINRT_EBO IOemSupportInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IOemSupportInfo>
{
    IOemSupportInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISmbiosInformationStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISmbiosInformationStatics>
{
    ISmbiosInformationStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISystemSupportDeviceInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISystemSupportDeviceInfo>
{
    ISystemSupportDeviceInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISystemSupportInfoStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISystemSupportInfoStatics>
{
    ISystemSupportInfoStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISystemSupportInfoStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISystemSupportInfoStatics2>
{
    ISystemSupportInfoStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
