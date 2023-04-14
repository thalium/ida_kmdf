// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.I2c.Provider.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.I2c.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::I2c {

struct I2cTransferResult
{
    Windows::Devices::I2c::I2cTransferStatus Status;
    uint32_t BytesTransferred;
};

inline bool operator==(I2cTransferResult const& left, I2cTransferResult const& right) noexcept
{
    return left.Status == right.Status && left.BytesTransferred == right.BytesTransferred;
}

inline bool operator!=(I2cTransferResult const& left, I2cTransferResult const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::I2c {

struct WINRT_EBO I2cConnectionSettings :
    Windows::Devices::I2c::II2cConnectionSettings
{
    I2cConnectionSettings(std::nullptr_t) noexcept {}
    I2cConnectionSettings(int32_t slaveAddress);
};

struct WINRT_EBO I2cController :
    Windows::Devices::I2c::II2cController
{
    I2cController(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>> GetControllersAsync(Windows::Devices::I2c::Provider::II2cProvider const& provider);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController> GetDefaultAsync();
};

struct WINRT_EBO I2cDevice :
    Windows::Devices::I2c::II2cDevice
{
    I2cDevice(std::nullptr_t) noexcept {}
    static hstring GetDeviceSelector();
    static hstring GetDeviceSelector(param::hstring const& friendlyName);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice> FromIdAsync(param::hstring const& deviceId, Windows::Devices::I2c::I2cConnectionSettings const& settings);
};

}
