// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Security.Authorization.AppCapabilityAccess.1.h"

WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess {

struct WINRT_EBO AppCapability :
    Windows::Security::Authorization::AppCapabilityAccess::IAppCapability
{
    AppCapability(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> RequestAccessForCapabilitiesForUserAsync(Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames);
    static Windows::Security::Authorization::AppCapabilityAccess::AppCapability Create(param::hstring const& capabilityName);
    static Windows::Security::Authorization::AppCapabilityAccess::AppCapability CreateWithProcessIdForUser(Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid);
};

struct WINRT_EBO AppCapabilityAccessChangedEventArgs :
    Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs
{
    AppCapabilityAccessChangedEventArgs(std::nullptr_t) noexcept {}
};

}
