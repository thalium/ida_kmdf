// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Security.Credentials.0.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.SystemAccess.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess {

struct WINRT_EBO IDeviceAccountConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDeviceAccountConfiguration>
{
    IDeviceAccountConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDeviceAccountConfiguration2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDeviceAccountConfiguration2>
{
    IDeviceAccountConfiguration2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataAccountSystemAccessManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataAccountSystemAccessManagerStatics>
{
    IUserDataAccountSystemAccessManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataAccountSystemAccessManagerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataAccountSystemAccessManagerStatics2>
{
    IUserDataAccountSystemAccessManagerStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
