// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Security.Authorization.AppCapabilityAccess.0.h"

WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess {

struct WINRT_EBO IAppCapability :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppCapability>
{
    IAppCapability(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppCapabilityAccessChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppCapabilityAccessChangedEventArgs>
{
    IAppCapabilityAccessChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppCapabilityStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppCapabilityStatics>
{
    IAppCapabilityStatics(std::nullptr_t = nullptr) noexcept {}
};

}
