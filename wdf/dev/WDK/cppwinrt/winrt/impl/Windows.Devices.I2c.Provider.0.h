// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider {

enum class ProviderI2cBusSpeed : int32_t
{
    StandardMode = 0,
    FastMode = 1,
};

enum class ProviderI2cSharingMode : int32_t
{
    Exclusive = 0,
    Shared = 1,
};

enum class ProviderI2cTransferStatus : int32_t
{
    FullTransfer = 0,
    PartialTransfer = 1,
    SlaveAddressNotAcknowledged = 2,
};

struct II2cControllerProvider;
struct II2cDeviceProvider;
struct II2cProvider;
struct IProviderI2cConnectionSettings;
struct ProviderI2cConnectionSettings;
struct ProviderI2cTransferResult;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::I2c::Provider::II2cControllerProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::I2c::Provider::II2cDeviceProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::I2c::Provider::II2cProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>{ using type = interface_category; };
template <> struct category<Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings>{ using type = class_category; };
template <> struct category<Windows::Devices::I2c::Provider::ProviderI2cBusSpeed>{ using type = enum_category; };
template <> struct category<Windows::Devices::I2c::Provider::ProviderI2cSharingMode>{ using type = enum_category; };
template <> struct category<Windows::Devices::I2c::Provider::ProviderI2cTransferStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>{ using type = struct_category<Windows::Devices::I2c::Provider::ProviderI2cTransferStatus,uint32_t>; };
template <> struct name<Windows::Devices::I2c::Provider::II2cControllerProvider>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.II2cControllerProvider" }; };
template <> struct name<Windows::Devices::I2c::Provider::II2cDeviceProvider>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.II2cDeviceProvider" }; };
template <> struct name<Windows::Devices::I2c::Provider::II2cProvider>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.II2cProvider" }; };
template <> struct name<Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.IProviderI2cConnectionSettings" }; };
template <> struct name<Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.ProviderI2cConnectionSettings" }; };
template <> struct name<Windows::Devices::I2c::Provider::ProviderI2cBusSpeed>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.ProviderI2cBusSpeed" }; };
template <> struct name<Windows::Devices::I2c::Provider::ProviderI2cSharingMode>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.ProviderI2cSharingMode" }; };
template <> struct name<Windows::Devices::I2c::Provider::ProviderI2cTransferStatus>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.ProviderI2cTransferStatus" }; };
template <> struct name<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>{ static constexpr auto & value{ L"Windows.Devices.I2c.Provider.ProviderI2cTransferResult" }; };
template <> struct guid_storage<Windows::Devices::I2c::Provider::II2cControllerProvider>{ static constexpr guid value{ 0x61C2BB82,0x4510,0x4163,{ 0xA8,0x7C,0x4E,0x15,0xA9,0x55,0x89,0x80 } }; };
template <> struct guid_storage<Windows::Devices::I2c::Provider::II2cDeviceProvider>{ static constexpr guid value{ 0xAD342654,0x57E8,0x453E,{ 0x83,0x29,0xD1,0xE4,0x47,0xD1,0x03,0xA9 } }; };
template <> struct guid_storage<Windows::Devices::I2c::Provider::II2cProvider>{ static constexpr guid value{ 0x6F13083E,0xBF62,0x4FE2,{ 0xA9,0x5A,0xF0,0x89,0x99,0x66,0x98,0x18 } }; };
template <> struct guid_storage<Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>{ static constexpr guid value{ 0xE9DB4E34,0xE510,0x44B7,{ 0x80,0x9D,0xF2,0xF8,0x5B,0x55,0x53,0x39 } }; };
template <> struct default_interface<Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings>{ using type = Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings; };

template <> struct abi<Windows::Devices::I2c::Provider::II2cControllerProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceProvider(void* settings, void** device) noexcept = 0;
};};

template <> struct abi<Windows::Devices::I2c::Provider::II2cDeviceProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Write(uint32_t __bufferSize, uint8_t* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL WritePartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL Read(uint32_t __bufferSize, uint8_t* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL ReadPartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL WriteRead(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept = 0;
    virtual int32_t WINRT_CALL WriteReadPartial(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::I2c::Provider::II2cProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetControllersAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SlaveAddress(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SlaveAddress(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_I2c_Provider_II2cControllerProvider
{
    Windows::Devices::I2c::Provider::II2cDeviceProvider GetDeviceProvider(Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const& settings) const;
};
template <> struct consume<Windows::Devices::I2c::Provider::II2cControllerProvider> { template <typename D> using type = consume_Windows_Devices_I2c_Provider_II2cControllerProvider<D>; };

template <typename D>
struct consume_Windows_Devices_I2c_Provider_II2cDeviceProvider
{
    hstring DeviceId() const;
    void Write(array_view<uint8_t const> buffer) const;
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult WritePartial(array_view<uint8_t const> buffer) const;
    void Read(array_view<uint8_t> buffer) const;
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult ReadPartial(array_view<uint8_t> buffer) const;
    void WriteRead(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const;
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult WriteReadPartial(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const;
};
template <> struct consume<Windows::Devices::I2c::Provider::II2cDeviceProvider> { template <typename D> using type = consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>; };

template <typename D>
struct consume_Windows_Devices_I2c_Provider_II2cProvider
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::Provider::II2cControllerProvider>> GetControllersAsync() const;
};
template <> struct consume<Windows::Devices::I2c::Provider::II2cProvider> { template <typename D> using type = consume_Windows_Devices_I2c_Provider_II2cProvider<D>; };

template <typename D>
struct consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings
{
    int32_t SlaveAddress() const;
    void SlaveAddress(int32_t value) const;
    Windows::Devices::I2c::Provider::ProviderI2cBusSpeed BusSpeed() const;
    void BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const& value) const;
    Windows::Devices::I2c::Provider::ProviderI2cSharingMode SharingMode() const;
    void SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode const& value) const;
};
template <> struct consume<Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> { template <typename D> using type = consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>; };

struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult
{
    Windows::Devices::I2c::Provider::ProviderI2cTransferStatus Status;
    uint32_t BytesTransferred;
};
template <> struct abi<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>{ using type = struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult; };


}
