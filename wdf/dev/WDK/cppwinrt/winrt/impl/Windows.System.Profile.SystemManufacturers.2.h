// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.Profile.SystemManufacturers.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers {

struct WINRT_EBO OemSupportInfo :
    Windows::System::Profile::SystemManufacturers::IOemSupportInfo
{
    OemSupportInfo(std::nullptr_t) noexcept {}
};

struct SmbiosInformation
{
    SmbiosInformation() = delete;
    static hstring SerialNumber();
};

struct WINRT_EBO SystemSupportDeviceInfo :
    Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo
{
    SystemSupportDeviceInfo(std::nullptr_t) noexcept {}
};

struct SystemSupportInfo
{
    SystemSupportInfo() = delete;
    static hstring LocalSystemEdition();
    static Windows::System::Profile::SystemManufacturers::OemSupportInfo OemSupportInfo();
    static Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo LocalDeviceInfo();
};

}
