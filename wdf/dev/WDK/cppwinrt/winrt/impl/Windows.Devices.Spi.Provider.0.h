// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider {

enum class ProviderSpiMode : int32_t
{
    Mode0 = 0,
    Mode1 = 1,
    Mode2 = 2,
    Mode3 = 3,
};

enum class ProviderSpiSharingMode : int32_t
{
    Exclusive = 0,
    Shared = 1,
};

struct IProviderSpiConnectionSettings;
struct IProviderSpiConnectionSettingsFactory;
struct ISpiControllerProvider;
struct ISpiDeviceProvider;
struct ISpiProvider;
struct ProviderSpiConnectionSettings;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>{ using type = interface_category; };
template <> struct category<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Spi::Provider::ISpiControllerProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::Spi::Provider::ISpiDeviceProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::Spi::Provider::ISpiProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>{ using type = class_category; };
template <> struct category<Windows::Devices::Spi::Provider::ProviderSpiMode>{ using type = enum_category; };
template <> struct category<Windows::Devices::Spi::Provider::ProviderSpiSharingMode>{ using type = enum_category; };
template <> struct name<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.IProviderSpiConnectionSettings" }; };
template <> struct name<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.IProviderSpiConnectionSettingsFactory" }; };
template <> struct name<Windows::Devices::Spi::Provider::ISpiControllerProvider>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ISpiControllerProvider" }; };
template <> struct name<Windows::Devices::Spi::Provider::ISpiDeviceProvider>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ISpiDeviceProvider" }; };
template <> struct name<Windows::Devices::Spi::Provider::ISpiProvider>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ISpiProvider" }; };
template <> struct name<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ProviderSpiConnectionSettings" }; };
template <> struct name<Windows::Devices::Spi::Provider::ProviderSpiMode>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ProviderSpiMode" }; };
template <> struct name<Windows::Devices::Spi::Provider::ProviderSpiSharingMode>{ static constexpr auto & value{ L"Windows.Devices.Spi.Provider.ProviderSpiSharingMode" }; };
template <> struct guid_storage<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>{ static constexpr guid value{ 0xF6034550,0xA542,0x4EC0,{ 0x96,0x01,0xA4,0xDD,0x68,0xF8,0x69,0x7B } }; };
template <> struct guid_storage<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>{ static constexpr guid value{ 0x66456B5A,0x0C79,0x43E3,{ 0x9F,0x3C,0xE5,0x97,0x80,0xAC,0x18,0xFA } }; };
template <> struct guid_storage<Windows::Devices::Spi::Provider::ISpiControllerProvider>{ static constexpr guid value{ 0xC1686504,0x02CE,0x4226,{ 0xA3,0x85,0x4F,0x11,0xFB,0x04,0xB4,0x1B } }; };
template <> struct guid_storage<Windows::Devices::Spi::Provider::ISpiDeviceProvider>{ static constexpr guid value{ 0x0D1C3443,0x304B,0x405C,{ 0xB4,0xF7,0xF5,0xAB,0x10,0x74,0x46,0x1E } }; };
template <> struct guid_storage<Windows::Devices::Spi::Provider::ISpiProvider>{ static constexpr guid value{ 0x96B461E2,0x77D4,0x48CE,{ 0xAA,0xA0,0x75,0x71,0x5A,0x83,0x62,0xCF } }; };
template <> struct default_interface<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>{ using type = Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings; };

template <> struct abi<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChipSelectLine(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ChipSelectLine(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mode(Windows::Devices::Spi::Provider::ProviderSpiMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mode(Windows::Devices::Spi::Provider::ProviderSpiMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataBitLength(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataBitLength(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClockFrequency(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ClockFrequency(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(int32_t chipSelectLine, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Spi::Provider::ISpiControllerProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceProvider(void* settings, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Spi::Provider::ISpiDeviceProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConnectionSettings(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Write(uint32_t __bufferSize, uint8_t* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL Read(uint32_t __bufferSize, uint8_t* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL TransferSequential(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept = 0;
    virtual int32_t WINRT_CALL TransferFullDuplex(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Spi::Provider::ISpiProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetControllersAsync(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings
{
    int32_t ChipSelectLine() const;
    void ChipSelectLine(int32_t value) const;
    Windows::Devices::Spi::Provider::ProviderSpiMode Mode() const;
    void Mode(Windows::Devices::Spi::Provider::ProviderSpiMode const& value) const;
    int32_t DataBitLength() const;
    void DataBitLength(int32_t value) const;
    int32_t ClockFrequency() const;
    void ClockFrequency(int32_t value) const;
    Windows::Devices::Spi::Provider::ProviderSpiSharingMode SharingMode() const;
    void SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode const& value) const;
};
template <> struct consume<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> { template <typename D> using type = consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>; };

template <typename D>
struct consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettingsFactory
{
    Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings Create(int32_t chipSelectLine) const;
};
template <> struct consume<Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> { template <typename D> using type = consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettingsFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Spi_Provider_ISpiControllerProvider
{
    Windows::Devices::Spi::Provider::ISpiDeviceProvider GetDeviceProvider(Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const& settings) const;
};
template <> struct consume<Windows::Devices::Spi::Provider::ISpiControllerProvider> { template <typename D> using type = consume_Windows_Devices_Spi_Provider_ISpiControllerProvider<D>; };

template <typename D>
struct consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider
{
    hstring DeviceId() const;
    Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings ConnectionSettings() const;
    void Write(array_view<uint8_t const> buffer) const;
    void Read(array_view<uint8_t> buffer) const;
    void TransferSequential(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const;
    void TransferFullDuplex(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const;
};
template <> struct consume<Windows::Devices::Spi::Provider::ISpiDeviceProvider> { template <typename D> using type = consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>; };

template <typename D>
struct consume_Windows_Devices_Spi_Provider_ISpiProvider
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::Provider::ISpiControllerProvider>> GetControllersAsync() const;
};
template <> struct consume<Windows::Devices::Spi::Provider::ISpiProvider> { template <typename D> using type = consume_Windows_Devices_Spi_Provider_ISpiProvider<D>; };

}
