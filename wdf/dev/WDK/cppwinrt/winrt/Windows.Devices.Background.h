// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Background.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Background_IDeviceServicingDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Background::IDeviceServicingDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Background_IDeviceServicingDetails<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Background::IDeviceServicingDetails)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Background_IDeviceServicingDetails<D>::ExpectedDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Background::IDeviceServicingDetails)->get_ExpectedDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Background_IDeviceUseDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Background::IDeviceUseDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Background_IDeviceUseDetails<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Background::IDeviceUseDetails)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Background::IDeviceServicingDetails> : produce_base<D, Windows::Devices::Background::IDeviceServicingDetails>
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

    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpectedDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpectedDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ExpectedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Background::IDeviceUseDetails> : produce_base<D, Windows::Devices::Background::IDeviceUseDetails>
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

    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Background {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Background::IDeviceServicingDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Background::IDeviceServicingDetails> {};
template<> struct hash<winrt::Windows::Devices::Background::IDeviceUseDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Background::IDeviceUseDetails> {};
template<> struct hash<winrt::Windows::Devices::Background::DeviceServicingDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Background::DeviceServicingDetails> {};
template<> struct hash<winrt::Windows::Devices::Background::DeviceUseDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Background::DeviceUseDetails> {};

}
