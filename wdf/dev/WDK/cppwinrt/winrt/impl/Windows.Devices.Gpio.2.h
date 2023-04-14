// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Gpio.Provider.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Gpio.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Gpio {

struct GpioChangeCount
{
    uint64_t Count;
    Windows::Foundation::TimeSpan RelativeTime;
};

inline bool operator==(GpioChangeCount const& left, GpioChangeCount const& right) noexcept
{
    return left.Count == right.Count && left.RelativeTime == right.RelativeTime;
}

inline bool operator!=(GpioChangeCount const& left, GpioChangeCount const& right) noexcept
{
    return !(left == right);
}

struct GpioChangeRecord
{
    Windows::Foundation::TimeSpan RelativeTime;
    Windows::Devices::Gpio::GpioPinEdge Edge;
};

inline bool operator==(GpioChangeRecord const& left, GpioChangeRecord const& right) noexcept
{
    return left.RelativeTime == right.RelativeTime && left.Edge == right.Edge;
}

inline bool operator!=(GpioChangeRecord const& left, GpioChangeRecord const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Gpio {

struct WINRT_EBO GpioChangeCounter :
    Windows::Devices::Gpio::IGpioChangeCounter
{
    GpioChangeCounter(std::nullptr_t) noexcept {}
    GpioChangeCounter(Windows::Devices::Gpio::GpioPin const& pin);
};

struct WINRT_EBO GpioChangeReader :
    Windows::Devices::Gpio::IGpioChangeReader
{
    GpioChangeReader(std::nullptr_t) noexcept {}
    GpioChangeReader(Windows::Devices::Gpio::GpioPin const& pin);
    GpioChangeReader(Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity);
};

struct WINRT_EBO GpioController :
    Windows::Devices::Gpio::IGpioController
{
    GpioController(std::nullptr_t) noexcept {}
    static Windows::Devices::Gpio::GpioController GetDefault();
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>> GetControllersAsync(Windows::Devices::Gpio::Provider::IGpioProvider const& provider);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController> GetDefaultAsync();
};

struct WINRT_EBO GpioPin :
    Windows::Devices::Gpio::IGpioPin
{
    GpioPin(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GpioPinValueChangedEventArgs :
    Windows::Devices::Gpio::IGpioPinValueChangedEventArgs
{
    GpioPinValueChangedEventArgs(std::nullptr_t) noexcept {}
};

}
