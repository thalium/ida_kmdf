// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Security.DataProtection.0.h"

WINRT_EXPORT namespace winrt::Windows::Security::DataProtection {

struct WINRT_EBO IUserDataAvailabilityStateChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataAvailabilityStateChangedEventArgs>
{
    IUserDataAvailabilityStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataBufferUnprotectResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataBufferUnprotectResult>
{
    IUserDataBufferUnprotectResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataProtectionManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataProtectionManager>
{
    IUserDataProtectionManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataProtectionManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataProtectionManagerStatics>
{
    IUserDataProtectionManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IUserDataStorageItemProtectionInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IUserDataStorageItemProtectionInfo>
{
    IUserDataStorageItemProtectionInfo(std::nullptr_t = nullptr) noexcept {}
};

}
