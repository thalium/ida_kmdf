// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider {

struct ProviderI2cTransferResult
{
    Windows::Devices::I2c::Provider::ProviderI2cTransferStatus Status;
    uint32_t BytesTransferred;
};

inline bool operator==(ProviderI2cTransferResult const& left, ProviderI2cTransferResult const& right) noexcept
{
    return left.Status == right.Status && left.BytesTransferred == right.BytesTransferred;
}

inline bool operator!=(ProviderI2cTransferResult const& left, ProviderI2cTransferResult const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider {

struct WINRT_EBO ProviderI2cConnectionSettings :
    Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings
{
    ProviderI2cConnectionSettings(std::nullptr_t) noexcept {}
};

}
