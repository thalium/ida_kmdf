// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Security.DataProtection.1.h"

WINRT_EXPORT namespace winrt::Windows::Security::DataProtection {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Security::DataProtection {

struct WINRT_EBO UserDataAvailabilityStateChangedEventArgs :
    Windows::Security::DataProtection::IUserDataAvailabilityStateChangedEventArgs
{
    UserDataAvailabilityStateChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserDataBufferUnprotectResult :
    Windows::Security::DataProtection::IUserDataBufferUnprotectResult
{
    UserDataBufferUnprotectResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO UserDataProtectionManager :
    Windows::Security::DataProtection::IUserDataProtectionManager
{
    UserDataProtectionManager(std::nullptr_t) noexcept {}
    static Windows::Security::DataProtection::UserDataProtectionManager TryGetDefault();
    static Windows::Security::DataProtection::UserDataProtectionManager TryGetForUser(Windows::System::User const& user);
};

struct WINRT_EBO UserDataStorageItemProtectionInfo :
    Windows::Security::DataProtection::IUserDataStorageItemProtectionInfo
{
    UserDataStorageItemProtectionInfo(std::nullptr_t) noexcept {}
};

}
