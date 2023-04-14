// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Custom.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Devices_Custom_ICustomDevice<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDevice)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Devices_Custom_ICustomDevice<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDevice)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_Custom_ICustomDevice<D>::SendIOControlAsync(Windows::Devices::Custom::IIOControlCode const& ioControlCode, Windows::Storage::Streams::IBuffer const& inputBuffer, Windows::Storage::Streams::IBuffer const& outputBuffer) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDevice)->SendIOControlAsync(get_abi(ioControlCode), get_abi(inputBuffer), get_abi(outputBuffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_Custom_ICustomDevice<D>::TrySendIOControlAsync(Windows::Devices::Custom::IIOControlCode const& ioControlCode, Windows::Storage::Streams::IBuffer const& inputBuffer, Windows::Storage::Streams::IBuffer const& outputBuffer) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDevice)->TrySendIOControlAsync(get_abi(ioControlCode), get_abi(inputBuffer), get_abi(outputBuffer), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Custom_ICustomDeviceStatics<D>::GetDeviceSelector(winrt::guid const& classGuid) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDeviceStatics)->GetDeviceSelector(get_abi(classGuid), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice> consume_Windows_Devices_Custom_ICustomDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId, Windows::Devices::Custom::DeviceAccessMode const& desiredAccess, Windows::Devices::Custom::DeviceSharingMode const& sharingMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::ICustomDeviceStatics)->FromIdAsync(get_abi(deviceId), get_abi(desiredAccess), get_abi(sharingMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Custom::IOControlAccessMode consume_Windows_Devices_Custom_IIOControlCode<D>::AccessMode() const
{
    Windows::Devices::Custom::IOControlAccessMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCode)->get_AccessMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Custom::IOControlBufferingMethod consume_Windows_Devices_Custom_IIOControlCode<D>::BufferingMethod() const
{
    Windows::Devices::Custom::IOControlBufferingMethod value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCode)->get_BufferingMethod(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Custom_IIOControlCode<D>::Function() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCode)->get_Function(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Custom_IIOControlCode<D>::DeviceType() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCode)->get_DeviceType(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Custom_IIOControlCode<D>::ControlCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCode)->get_ControlCode(&value));
    return value;
}

template <typename D> Windows::Devices::Custom::IOControlCode consume_Windows_Devices_Custom_IIOControlCodeFactory<D>::CreateIOControlCode(uint16_t deviceType, uint16_t function, Windows::Devices::Custom::IOControlAccessMode const& accessMode, Windows::Devices::Custom::IOControlBufferingMethod const& bufferingMethod) const
{
    Windows::Devices::Custom::IOControlCode instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IIOControlCodeFactory)->CreateIOControlCode(deviceType, function, get_abi(accessMode), get_abi(bufferingMethod), put_abi(instance)));
    return instance;
}

template <typename D> uint16_t consume_Windows_Devices_Custom_IKnownDeviceTypesStatics<D>::Unknown() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Custom::IKnownDeviceTypesStatics)->get_Unknown(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Custom::ICustomDevice> : produce_base<D, Windows::Devices::Custom::ICustomDevice>
{
    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendIOControlAsync(void* ioControlCode, void* inputBuffer, void* outputBuffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendIOControlAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Devices::Custom::IIOControlCode const, Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().SendIOControlAsync(*reinterpret_cast<Windows::Devices::Custom::IIOControlCode const*>(&ioControlCode), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&inputBuffer), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&outputBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySendIOControlAsync(void* ioControlCode, void* inputBuffer, void* outputBuffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySendIOControlAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Custom::IIOControlCode const, Windows::Storage::Streams::IBuffer const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySendIOControlAsync(*reinterpret_cast<Windows::Devices::Custom::IIOControlCode const*>(&ioControlCode), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&inputBuffer), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&outputBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Custom::ICustomDeviceStatics> : produce_base<D, Windows::Devices::Custom::ICustomDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(winrt::guid classGuid, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), winrt::guid const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::guid const*>(&classGuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, Windows::Devices::Custom::DeviceAccessMode desiredAccess, Windows::Devices::Custom::DeviceSharingMode sharingMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice>), hstring const, Windows::Devices::Custom::DeviceAccessMode const, Windows::Devices::Custom::DeviceSharingMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Devices::Custom::DeviceAccessMode const*>(&desiredAccess), *reinterpret_cast<Windows::Devices::Custom::DeviceSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Custom::IIOControlCode> : produce_base<D, Windows::Devices::Custom::IIOControlCode>
{
    int32_t WINRT_CALL get_AccessMode(Windows::Devices::Custom::IOControlAccessMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessMode, WINRT_WRAP(Windows::Devices::Custom::IOControlAccessMode));
            *value = detach_from<Windows::Devices::Custom::IOControlAccessMode>(this->shim().AccessMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferingMethod(Windows::Devices::Custom::IOControlBufferingMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingMethod, WINRT_WRAP(Windows::Devices::Custom::IOControlBufferingMethod));
            *value = detach_from<Windows::Devices::Custom::IOControlBufferingMethod>(this->shim().BufferingMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Function(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Function, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Function());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceType(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceType, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().DeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ControlCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Custom::IIOControlCodeFactory> : produce_base<D, Windows::Devices::Custom::IIOControlCodeFactory>
{
    int32_t WINRT_CALL CreateIOControlCode(uint16_t deviceType, uint16_t function, Windows::Devices::Custom::IOControlAccessMode accessMode, Windows::Devices::Custom::IOControlBufferingMethod bufferingMethod, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateIOControlCode, WINRT_WRAP(Windows::Devices::Custom::IOControlCode), uint16_t, uint16_t, Windows::Devices::Custom::IOControlAccessMode const&, Windows::Devices::Custom::IOControlBufferingMethod const&);
            *instance = detach_from<Windows::Devices::Custom::IOControlCode>(this->shim().CreateIOControlCode(deviceType, function, *reinterpret_cast<Windows::Devices::Custom::IOControlAccessMode const*>(&accessMode), *reinterpret_cast<Windows::Devices::Custom::IOControlBufferingMethod const*>(&bufferingMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Custom::IKnownDeviceTypesStatics> : produce_base<D, Windows::Devices::Custom::IKnownDeviceTypesStatics>
{
    int32_t WINRT_CALL get_Unknown(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unknown, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Unknown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Custom {

inline hstring CustomDevice::GetDeviceSelector(winrt::guid const& classGuid)
{
    return impl::call_factory<CustomDevice, Windows::Devices::Custom::ICustomDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(classGuid); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Custom::CustomDevice> CustomDevice::FromIdAsync(param::hstring const& deviceId, Windows::Devices::Custom::DeviceAccessMode const& desiredAccess, Windows::Devices::Custom::DeviceSharingMode const& sharingMode)
{
    return impl::call_factory<CustomDevice, Windows::Devices::Custom::ICustomDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId, desiredAccess, sharingMode); });
}

inline IOControlCode::IOControlCode(uint16_t deviceType, uint16_t function, Windows::Devices::Custom::IOControlAccessMode const& accessMode, Windows::Devices::Custom::IOControlBufferingMethod const& bufferingMethod) :
    IOControlCode(impl::call_factory<IOControlCode, Windows::Devices::Custom::IIOControlCodeFactory>([&](auto&& f) { return f.CreateIOControlCode(deviceType, function, accessMode, bufferingMethod); }))
{}

inline uint16_t KnownDeviceTypes::Unknown()
{
    return impl::call_factory<KnownDeviceTypes, Windows::Devices::Custom::IKnownDeviceTypesStatics>([&](auto&& f) { return f.Unknown(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Custom::ICustomDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::ICustomDevice> {};
template<> struct hash<winrt::Windows::Devices::Custom::ICustomDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::ICustomDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Custom::IIOControlCode> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::IIOControlCode> {};
template<> struct hash<winrt::Windows::Devices::Custom::IIOControlCodeFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::IIOControlCodeFactory> {};
template<> struct hash<winrt::Windows::Devices::Custom::IKnownDeviceTypesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::IKnownDeviceTypesStatics> {};
template<> struct hash<winrt::Windows::Devices::Custom::CustomDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::CustomDevice> {};
template<> struct hash<winrt::Windows::Devices::Custom::IOControlCode> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::IOControlCode> {};
template<> struct hash<winrt::Windows::Devices::Custom::KnownDeviceTypes> : winrt::impl::hash_base<winrt::Windows::Devices::Custom::KnownDeviceTypes> {};

}
