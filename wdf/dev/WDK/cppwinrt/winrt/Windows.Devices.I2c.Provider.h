// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.2.h"
#include "winrt/Windows.Devices.I2c.h"

namespace winrt::impl {

template <typename D> Windows::Devices::I2c::Provider::II2cDeviceProvider consume_Windows_Devices_I2c_Provider_II2cControllerProvider<D>::GetDeviceProvider(Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const& settings) const
{
    Windows::Devices::I2c::Provider::II2cDeviceProvider device{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cControllerProvider)->GetDeviceProvider(get_abi(settings), put_abi(device)));
    return device;
}

template <typename D> hstring consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::Write(array_view<uint8_t const> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->Write(buffer.size(), get_abi(buffer)));
}

template <typename D> Windows::Devices::I2c::Provider::ProviderI2cTransferResult consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WritePartial(array_view<uint8_t const> buffer) const
{
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->WritePartial(buffer.size(), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::Read(array_view<uint8_t> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->Read(buffer.size(), get_abi(buffer)));
}

template <typename D> Windows::Devices::I2c::Provider::ProviderI2cTransferResult consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::ReadPartial(array_view<uint8_t> buffer) const
{
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->ReadPartial(buffer.size(), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WriteRead(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->WriteRead(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> Windows::Devices::I2c::Provider::ProviderI2cTransferResult consume_Windows_Devices_I2c_Provider_II2cDeviceProvider<D>::WriteReadPartial(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    Windows::Devices::I2c::Provider::ProviderI2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cDeviceProvider)->WriteReadPartial(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::Provider::II2cControllerProvider>> consume_Windows_Devices_I2c_Provider_II2cProvider<D>::GetControllersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::Provider::II2cControllerProvider>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::II2cProvider)->GetControllersAsync(put_abi(operation)));
    return operation;
}

template <typename D> int32_t consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SlaveAddress() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_SlaveAddress(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SlaveAddress(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_SlaveAddress(value));
}

template <typename D> Windows::Devices::I2c::Provider::ProviderI2cBusSpeed consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::BusSpeed() const
{
    Windows::Devices::I2c::Provider::ProviderI2cBusSpeed value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_BusSpeed(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_BusSpeed(get_abi(value)));
}

template <typename D> Windows::Devices::I2c::Provider::ProviderI2cSharingMode consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SharingMode() const
{
    Windows::Devices::I2c::Provider::ProviderI2cSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_Provider_IProviderI2cConnectionSettings<D>::SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings)->put_SharingMode(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Devices::I2c::Provider::II2cControllerProvider> : produce_base<D, Windows::Devices::I2c::Provider::II2cControllerProvider>
{
    int32_t WINRT_CALL GetDeviceProvider(void* settings, void** device) noexcept final
    {
        try
        {
            *device = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceProvider, WINRT_WRAP(Windows::Devices::I2c::Provider::II2cDeviceProvider), Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const&);
            *device = detach_from<Windows::Devices::I2c::Provider::II2cDeviceProvider>(this->shim().GetDeviceProvider(*reinterpret_cast<Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::Provider::II2cDeviceProvider> : produce_base<D, Windows::Devices::I2c::Provider::II2cDeviceProvider>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Write(uint32_t __bufferSize, uint8_t* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Write, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().Write(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WritePartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WritePartial, WINRT_WRAP(Windows::Devices::I2c::Provider::ProviderI2cTransferResult), array_view<uint8_t const>);
            *result = detach_from<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().WritePartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Read(uint32_t __bufferSize, uint8_t* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Read, WINRT_WRAP(void), array_view<uint8_t>);
            this->shim().Read(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadPartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadPartial, WINRT_WRAP(Windows::Devices::I2c::Provider::ProviderI2cTransferResult), array_view<uint8_t>);
            *result = detach_from<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().ReadPartial(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteRead(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteRead, WINRT_WRAP(void), array_view<uint8_t const>, array_view<uint8_t>);
            this->shim().WriteRead(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteReadPartial(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer, struct struct_Windows_Devices_I2c_Provider_ProviderI2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteReadPartial, WINRT_WRAP(Windows::Devices::I2c::Provider::ProviderI2cTransferResult), array_view<uint8_t const>, array_view<uint8_t>);
            *result = detach_from<Windows::Devices::I2c::Provider::ProviderI2cTransferResult>(this->shim().WriteReadPartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::Provider::II2cProvider> : produce_base<D, Windows::Devices::I2c::Provider::II2cProvider>
{
    int32_t WINRT_CALL GetControllersAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::Provider::II2cControllerProvider>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::Provider::II2cControllerProvider>>>(this->shim().GetControllersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> : produce_base<D, Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings>
{
    int32_t WINRT_CALL get_SlaveAddress(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlaveAddress, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SlaveAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SlaveAddress(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlaveAddress, WINRT_WRAP(void), int32_t);
            this->shim().SlaveAddress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusSpeed, WINRT_WRAP(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed));
            *value = detach_from<Windows::Devices::I2c::Provider::ProviderI2cBusSpeed>(this->shim().BusSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BusSpeed(Windows::Devices::I2c::Provider::ProviderI2cBusSpeed value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusSpeed, WINRT_WRAP(void), Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const&);
            this->shim().BusSpeed(*reinterpret_cast<Windows::Devices::I2c::Provider::ProviderI2cBusSpeed const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::I2c::Provider::ProviderI2cSharingMode));
            *value = detach_from<Windows::Devices::I2c::Provider::ProviderI2cSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharingMode(Windows::Devices::I2c::Provider::ProviderI2cSharingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(void), Windows::Devices::I2c::Provider::ProviderI2cSharingMode const&);
            this->shim().SharingMode(*reinterpret_cast<Windows::Devices::I2c::Provider::ProviderI2cSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::I2c::Provider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::Provider::II2cControllerProvider> {};
template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::Provider::II2cDeviceProvider> {};
template<> struct hash<winrt::Windows::Devices::I2c::Provider::II2cProvider> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::Provider::II2cProvider> {};
template<> struct hash<winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::Provider::IProviderI2cConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::Provider::ProviderI2cConnectionSettings> {};

}
