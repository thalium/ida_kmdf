// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Security.Cryptography.DataProtection.0.h"

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::DataProtection {

struct WINRT_EBO IDataProtectionProvider :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDataProtectionProvider>
{
    IDataProtectionProvider(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDataProtectionProviderFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDataProtectionProviderFactory>
{
    IDataProtectionProviderFactory(std::nullptr_t = nullptr) noexcept {}
};

}
