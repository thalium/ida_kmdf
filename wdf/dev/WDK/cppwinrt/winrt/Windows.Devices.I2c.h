// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.I2c.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.I2c.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SlaveAddress() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->get_SlaveAddress(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SlaveAddress(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->put_SlaveAddress(value));
}

template <typename D> Windows::Devices::I2c::I2cBusSpeed consume_Windows_Devices_I2c_II2cConnectionSettings<D>::BusSpeed() const
{
    Windows::Devices::I2c::I2cBusSpeed value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->get_BusSpeed(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_II2cConnectionSettings<D>::BusSpeed(Windows::Devices::I2c::I2cBusSpeed const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->put_BusSpeed(get_abi(value)));
}

template <typename D> Windows::Devices::I2c::I2cSharingMode consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SharingMode() const
{
    Windows::Devices::I2c::I2cSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_II2cConnectionSettings<D>::SharingMode(Windows::Devices::I2c::I2cSharingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettings)->put_SharingMode(get_abi(value)));
}

template <typename D> Windows::Devices::I2c::I2cConnectionSettings consume_Windows_Devices_I2c_II2cConnectionSettingsFactory<D>::Create(int32_t slaveAddress) const
{
    Windows::Devices::I2c::I2cConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cConnectionSettingsFactory)->Create(slaveAddress, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::I2c::I2cDevice consume_Windows_Devices_I2c_II2cController<D>::GetDevice(Windows::Devices::I2c::I2cConnectionSettings const& settings) const
{
    Windows::Devices::I2c::I2cDevice device{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cController)->GetDevice(get_abi(settings), put_abi(device)));
    return device;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>> consume_Windows_Devices_I2c_II2cControllerStatics<D>::GetControllersAsync(Windows::Devices::I2c::Provider::II2cProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cControllerStatics)->GetControllersAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController> consume_Windows_Devices_I2c_II2cControllerStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cControllerStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_I2c_II2cDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::I2c::I2cConnectionSettings consume_Windows_Devices_I2c_II2cDevice<D>::ConnectionSettings() const
{
    Windows::Devices::I2c::I2cConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->get_ConnectionSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_I2c_II2cDevice<D>::Write(array_view<uint8_t const> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->Write(buffer.size(), get_abi(buffer)));
}

template <typename D> Windows::Devices::I2c::I2cTransferResult consume_Windows_Devices_I2c_II2cDevice<D>::WritePartial(array_view<uint8_t const> buffer) const
{
    Windows::Devices::I2c::I2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->WritePartial(buffer.size(), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_I2c_II2cDevice<D>::Read(array_view<uint8_t> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->Read(buffer.size(), get_abi(buffer)));
}

template <typename D> Windows::Devices::I2c::I2cTransferResult consume_Windows_Devices_I2c_II2cDevice<D>::ReadPartial(array_view<uint8_t> buffer) const
{
    Windows::Devices::I2c::I2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->ReadPartial(buffer.size(), get_abi(buffer), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_I2c_II2cDevice<D>::WriteRead(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->WriteRead(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> Windows::Devices::I2c::I2cTransferResult consume_Windows_Devices_I2c_II2cDevice<D>::WriteReadPartial(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    Windows::Devices::I2c::I2cTransferResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDevice)->WriteReadPartial(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_I2c_II2cDeviceStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDeviceStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_I2c_II2cDeviceStatics<D>::GetDeviceSelector(param::hstring const& friendlyName) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDeviceStatics)->GetDeviceSelectorFromFriendlyName(get_abi(friendlyName), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice> consume_Windows_Devices_I2c_II2cDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId, Windows::Devices::I2c::I2cConnectionSettings const& settings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::I2c::II2cDeviceStatics)->FromIdAsync(get_abi(deviceId), get_abi(settings), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cConnectionSettings> : produce_base<D, Windows::Devices::I2c::II2cConnectionSettings>
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

    int32_t WINRT_CALL get_BusSpeed(Windows::Devices::I2c::I2cBusSpeed* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusSpeed, WINRT_WRAP(Windows::Devices::I2c::I2cBusSpeed));
            *value = detach_from<Windows::Devices::I2c::I2cBusSpeed>(this->shim().BusSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BusSpeed(Windows::Devices::I2c::I2cBusSpeed value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusSpeed, WINRT_WRAP(void), Windows::Devices::I2c::I2cBusSpeed const&);
            this->shim().BusSpeed(*reinterpret_cast<Windows::Devices::I2c::I2cBusSpeed const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::I2c::I2cSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::I2c::I2cSharingMode));
            *value = detach_from<Windows::Devices::I2c::I2cSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharingMode(Windows::Devices::I2c::I2cSharingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(void), Windows::Devices::I2c::I2cSharingMode const&);
            this->shim().SharingMode(*reinterpret_cast<Windows::Devices::I2c::I2cSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cConnectionSettingsFactory> : produce_base<D, Windows::Devices::I2c::II2cConnectionSettingsFactory>
{
    int32_t WINRT_CALL Create(int32_t slaveAddress, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::I2c::I2cConnectionSettings), int32_t);
            *value = detach_from<Windows::Devices::I2c::I2cConnectionSettings>(this->shim().Create(slaveAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cController> : produce_base<D, Windows::Devices::I2c::II2cController>
{
    int32_t WINRT_CALL GetDevice(void* settings, void** device) noexcept final
    {
        try
        {
            *device = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDevice, WINRT_WRAP(Windows::Devices::I2c::I2cDevice), Windows::Devices::I2c::I2cConnectionSettings const&);
            *device = detach_from<Windows::Devices::I2c::I2cDevice>(this->shim().GetDevice(*reinterpret_cast<Windows::Devices::I2c::I2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cControllerStatics> : produce_base<D, Windows::Devices::I2c::II2cControllerStatics>
{
    int32_t WINRT_CALL GetControllersAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>>), Windows::Devices::I2c::Provider::II2cProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>>>(this->shim().GetControllersAsync(*reinterpret_cast<Windows::Devices::I2c::Provider::II2cProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cDevice> : produce_base<D, Windows::Devices::I2c::II2cDevice>
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

    int32_t WINRT_CALL get_ConnectionSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionSettings, WINRT_WRAP(Windows::Devices::I2c::I2cConnectionSettings));
            *value = detach_from<Windows::Devices::I2c::I2cConnectionSettings>(this->shim().ConnectionSettings());
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

    int32_t WINRT_CALL WritePartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WritePartial, WINRT_WRAP(Windows::Devices::I2c::I2cTransferResult), array_view<uint8_t const>);
            *result = detach_from<Windows::Devices::I2c::I2cTransferResult>(this->shim().WritePartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
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

    int32_t WINRT_CALL ReadPartial(uint32_t __bufferSize, uint8_t* buffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadPartial, WINRT_WRAP(Windows::Devices::I2c::I2cTransferResult), array_view<uint8_t>);
            *result = detach_from<Windows::Devices::I2c::I2cTransferResult>(this->shim().ReadPartial(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize)));
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

    int32_t WINRT_CALL WriteReadPartial(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer, struct struct_Windows_Devices_I2c_I2cTransferResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteReadPartial, WINRT_WRAP(Windows::Devices::I2c::I2cTransferResult), array_view<uint8_t const>, array_view<uint8_t>);
            *result = detach_from<Windows::Devices::I2c::I2cTransferResult>(this->shim().WriteReadPartial(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::I2c::II2cDeviceStatics> : produce_base<D, Windows::Devices::I2c::II2cDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromFriendlyName(void* friendlyName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&friendlyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void* settings, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice>), hstring const, Windows::Devices::I2c::I2cConnectionSettings const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Devices::I2c::I2cConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::I2c {

inline I2cConnectionSettings::I2cConnectionSettings(int32_t slaveAddress) :
    I2cConnectionSettings(impl::call_factory<I2cConnectionSettings, Windows::Devices::I2c::II2cConnectionSettingsFactory>([&](auto&& f) { return f.Create(slaveAddress); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::I2c::I2cController>> I2cController::GetControllersAsync(Windows::Devices::I2c::Provider::II2cProvider const& provider)
{
    return impl::call_factory<I2cController, Windows::Devices::I2c::II2cControllerStatics>([&](auto&& f) { return f.GetControllersAsync(provider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cController> I2cController::GetDefaultAsync()
{
    return impl::call_factory<I2cController, Windows::Devices::I2c::II2cControllerStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring I2cDevice::GetDeviceSelector()
{
    return impl::call_factory<I2cDevice, Windows::Devices::I2c::II2cDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring I2cDevice::GetDeviceSelector(param::hstring const& friendlyName)
{
    return impl::call_factory<I2cDevice, Windows::Devices::I2c::II2cDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(friendlyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::I2c::I2cDevice> I2cDevice::FromIdAsync(param::hstring const& deviceId, Windows::Devices::I2c::I2cConnectionSettings const& settings)
{
    return impl::call_factory<I2cDevice, Windows::Devices::I2c::II2cDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId, settings); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::I2c::II2cConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cConnectionSettingsFactory> {};
template<> struct hash<winrt::Windows::Devices::I2c::II2cController> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cController> {};
template<> struct hash<winrt::Windows::Devices::I2c::II2cControllerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cControllerStatics> {};
template<> struct hash<winrt::Windows::Devices::I2c::II2cDevice> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cDevice> {};
template<> struct hash<winrt::Windows::Devices::I2c::II2cDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::II2cDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::I2c::I2cConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::I2cConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::I2c::I2cController> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::I2cController> {};
template<> struct hash<winrt::Windows::Devices::I2c::I2cDevice> : winrt::impl::hash_base<winrt::Windows::Devices::I2c::I2cDevice> {};

}
