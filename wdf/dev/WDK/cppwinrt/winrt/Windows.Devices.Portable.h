// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Devices.Portable.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Portable_IServiceDeviceStatics<D>::GetDeviceSelector(Windows::Devices::Portable::ServiceDeviceType const& serviceType) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Portable::IServiceDeviceStatics)->GetDeviceSelector(get_abi(serviceType), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Portable_IServiceDeviceStatics<D>::GetDeviceSelectorFromServiceId(winrt::guid const& serviceId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Portable::IServiceDeviceStatics)->GetDeviceSelectorFromServiceId(get_abi(serviceId), put_abi(selector)));
    return selector;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Devices_Portable_IStorageDeviceStatics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Storage::StorageFolder deviceRoot{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Portable::IStorageDeviceStatics)->FromId(get_abi(deviceId), put_abi(deviceRoot)));
    return deviceRoot;
}

template <typename D> hstring consume_Windows_Devices_Portable_IStorageDeviceStatics<D>::GetDeviceSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Portable::IStorageDeviceStatics)->GetDeviceSelector(put_abi(selector)));
    return selector;
}

template <typename D>
struct produce<D, Windows::Devices::Portable::IServiceDeviceStatics> : produce_base<D, Windows::Devices::Portable::IServiceDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(Windows::Devices::Portable::ServiceDeviceType serviceType, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Portable::ServiceDeviceType const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Portable::ServiceDeviceType const*>(&serviceType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromServiceId(winrt::guid serviceId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromServiceId, WINRT_WRAP(hstring), winrt::guid const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorFromServiceId(*reinterpret_cast<winrt::guid const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Portable::IStorageDeviceStatics> : produce_base<D, Windows::Devices::Portable::IStorageDeviceStatics>
{
    int32_t WINRT_CALL FromId(void* deviceId, void** deviceRoot) noexcept final
    {
        try
        {
            *deviceRoot = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Storage::StorageFolder), hstring const&);
            *deviceRoot = detach_from<Windows::Storage::StorageFolder>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Portable {

inline hstring ServiceDevice::GetDeviceSelector(Windows::Devices::Portable::ServiceDeviceType const& serviceType)
{
    return impl::call_factory<ServiceDevice, Windows::Devices::Portable::IServiceDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(serviceType); });
}

inline hstring ServiceDevice::GetDeviceSelectorFromServiceId(winrt::guid const& serviceId)
{
    return impl::call_factory<ServiceDevice, Windows::Devices::Portable::IServiceDeviceStatics>([&](auto&& f) { return f.GetDeviceSelectorFromServiceId(serviceId); });
}

inline Windows::Storage::StorageFolder StorageDevice::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<StorageDevice, Windows::Devices::Portable::IStorageDeviceStatics>([&](auto&& f) { return f.FromId(deviceId); });
}

inline hstring StorageDevice::GetDeviceSelector()
{
    return impl::call_factory<StorageDevice, Windows::Devices::Portable::IStorageDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Portable::IServiceDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Portable::IServiceDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Portable::IStorageDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Portable::IStorageDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Portable::ServiceDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Portable::ServiceDevice> {};
template<> struct hash<winrt::Windows::Devices::Portable::StorageDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Portable::StorageDevice> {};

}
