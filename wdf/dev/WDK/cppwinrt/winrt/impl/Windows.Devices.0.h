// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Adc::Provider {

struct IAdcControllerProvider;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Gpio::Provider {

struct IGpioControllerProvider;

}

WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider {

struct II2cControllerProvider;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Pwm::Provider {

struct IPwmControllerProvider;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider {

struct ISpiControllerProvider;

}

WINRT_EXPORT namespace winrt::Windows::Devices {

struct ILowLevelDevicesAggregateProvider;
struct ILowLevelDevicesAggregateProviderFactory;
struct ILowLevelDevicesController;
struct ILowLevelDevicesControllerStatics;
struct LowLevelDevicesAggregateProvider;
struct LowLevelDevicesController;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::ILowLevelDevicesAggregateProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::ILowLevelDevicesAggregateProviderFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::ILowLevelDevicesController>{ using type = interface_category; };
template <> struct category<Windows::Devices::ILowLevelDevicesControllerStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::LowLevelDevicesAggregateProvider>{ using type = class_category; };
template <> struct category<Windows::Devices::LowLevelDevicesController>{ using type = class_category; };
template <> struct name<Windows::Devices::ILowLevelDevicesAggregateProvider>{ static constexpr auto & value{ L"Windows.Devices.ILowLevelDevicesAggregateProvider" }; };
template <> struct name<Windows::Devices::ILowLevelDevicesAggregateProviderFactory>{ static constexpr auto & value{ L"Windows.Devices.ILowLevelDevicesAggregateProviderFactory" }; };
template <> struct name<Windows::Devices::ILowLevelDevicesController>{ static constexpr auto & value{ L"Windows.Devices.ILowLevelDevicesController" }; };
template <> struct name<Windows::Devices::ILowLevelDevicesControllerStatics>{ static constexpr auto & value{ L"Windows.Devices.ILowLevelDevicesControllerStatics" }; };
template <> struct name<Windows::Devices::LowLevelDevicesAggregateProvider>{ static constexpr auto & value{ L"Windows.Devices.LowLevelDevicesAggregateProvider" }; };
template <> struct name<Windows::Devices::LowLevelDevicesController>{ static constexpr auto & value{ L"Windows.Devices.LowLevelDevicesController" }; };
template <> struct guid_storage<Windows::Devices::ILowLevelDevicesAggregateProvider>{ static constexpr guid value{ 0xA73E561C,0xAAC1,0x4EC7,{ 0xA8,0x52,0x47,0x9F,0x70,0x60,0xD0,0x1F } }; };
template <> struct guid_storage<Windows::Devices::ILowLevelDevicesAggregateProviderFactory>{ static constexpr guid value{ 0x9AC4AAF6,0x3473,0x465E,{ 0x96,0xD5,0x36,0x28,0x1A,0x2C,0x57,0xAF } }; };
template <> struct guid_storage<Windows::Devices::ILowLevelDevicesController>{ static constexpr guid value{ 0x2EC23DD4,0x179B,0x45DE,{ 0x9B,0x39,0x3A,0xE0,0x25,0x27,0xDE,0x52 } }; };
template <> struct guid_storage<Windows::Devices::ILowLevelDevicesControllerStatics>{ static constexpr guid value{ 0x093E926A,0xFCCB,0x4394,{ 0xA6,0x97,0x19,0xDE,0x63,0x7C,0x2D,0xB3 } }; };
template <> struct default_interface<Windows::Devices::LowLevelDevicesAggregateProvider>{ using type = Windows::Devices::ILowLevelDevicesAggregateProvider; };
template <> struct default_interface<Windows::Devices::LowLevelDevicesController>{ using type = Windows::Devices::ILowLevelDevicesController; };

template <> struct abi<Windows::Devices::ILowLevelDevicesAggregateProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdcControllerProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PwmControllerProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GpioControllerProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_I2cControllerProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpiControllerProvider(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::ILowLevelDevicesAggregateProviderFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* adc, void* pwm, void* gpio, void* i2c, void* spi, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::ILowLevelDevicesController>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::ILowLevelDevicesControllerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DefaultProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DefaultProvider(void* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_ILowLevelDevicesAggregateProvider
{
    Windows::Devices::Adc::Provider::IAdcControllerProvider AdcControllerProvider() const;
    Windows::Devices::Pwm::Provider::IPwmControllerProvider PwmControllerProvider() const;
    Windows::Devices::Gpio::Provider::IGpioControllerProvider GpioControllerProvider() const;
    Windows::Devices::I2c::Provider::II2cControllerProvider I2cControllerProvider() const;
    Windows::Devices::Spi::Provider::ISpiControllerProvider SpiControllerProvider() const;
};
template <> struct consume<Windows::Devices::ILowLevelDevicesAggregateProvider> { template <typename D> using type = consume_Windows_Devices_ILowLevelDevicesAggregateProvider<D>; };

template <typename D>
struct consume_Windows_Devices_ILowLevelDevicesAggregateProviderFactory
{
    Windows::Devices::LowLevelDevicesAggregateProvider Create(Windows::Devices::Adc::Provider::IAdcControllerProvider const& adc, Windows::Devices::Pwm::Provider::IPwmControllerProvider const& pwm, Windows::Devices::Gpio::Provider::IGpioControllerProvider const& gpio, Windows::Devices::I2c::Provider::II2cControllerProvider const& i2c, Windows::Devices::Spi::Provider::ISpiControllerProvider const& spi) const;
};
template <> struct consume<Windows::Devices::ILowLevelDevicesAggregateProviderFactory> { template <typename D> using type = consume_Windows_Devices_ILowLevelDevicesAggregateProviderFactory<D>; };

template <typename D>
struct consume_Windows_Devices_ILowLevelDevicesController
{
};
template <> struct consume<Windows::Devices::ILowLevelDevicesController> { template <typename D> using type = consume_Windows_Devices_ILowLevelDevicesController<D>; };

template <typename D>
struct consume_Windows_Devices_ILowLevelDevicesControllerStatics
{
    Windows::Devices::ILowLevelDevicesAggregateProvider DefaultProvider() const;
    void DefaultProvider(Windows::Devices::ILowLevelDevicesAggregateProvider const& value) const;
};
template <> struct consume<Windows::Devices::ILowLevelDevicesControllerStatics> { template <typename D> using type = consume_Windows_Devices_ILowLevelDevicesControllerStatics<D>; };

}
