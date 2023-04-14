// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Radios.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> consume_Windows_Devices_Radios_IRadio<D>::SetStateAsync(Windows::Devices::Radios::RadioState const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> retval{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadio)->SetStateAsync(get_abi(value), put_abi(retval)));
    return retval;
}

template <typename D> winrt::event_token consume_Windows_Devices_Radios_IRadio<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadio)->add_StateChanged(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Radios_IRadio<D>::StateChanged_revoker consume_Windows_Devices_Radios_IRadio<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Devices_Radios_IRadio<D>::StateChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Radios::IRadio)->remove_StateChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Devices::Radios::RadioState consume_Windows_Devices_Radios_IRadio<D>::State() const
{
    Windows::Devices::Radios::RadioState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadio)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Radios_IRadio<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadio)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Radios::RadioKind consume_Windows_Devices_Radios_IRadio<D>::Kind() const
{
    Windows::Devices::Radios::RadioKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadio)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>> consume_Windows_Devices_Radios_IRadioStatics<D>::GetRadiosAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadioStatics)->GetRadiosAsync(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Radios_IRadioStatics<D>::GetDeviceSelector() const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadioStatics)->GetDeviceSelector(put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> consume_Windows_Devices_Radios_IRadioStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadioStatics)->FromIdAsync(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> consume_Windows_Devices_Radios_IRadioStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Radios::IRadioStatics)->RequestAccessAsync(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Radios::IRadio> : produce_base<D, Windows::Devices::Radios::IRadio>
{
    int32_t WINRT_CALL SetStateAsync(Windows::Devices::Radios::RadioState value, void** retval) noexcept final
    {
        try
        {
            *retval = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus>), Windows::Devices::Radios::RadioState const);
            *retval = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus>>(this->shim().SetStateAsync(*reinterpret_cast<Windows::Devices::Radios::RadioState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL get_State(Windows::Devices::Radios::RadioState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::Radios::RadioState));
            *value = detach_from<Windows::Devices::Radios::RadioState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Devices::Radios::RadioKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Devices::Radios::RadioKind));
            *value = detach_from<Windows::Devices::Radios::RadioKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Radios::IRadioStatics> : produce_base<D, Windows::Devices::Radios::IRadioStatics>
{
    int32_t WINRT_CALL GetRadiosAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRadiosAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>>>(this->shim().GetRadiosAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Radios {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>> Radio::GetRadiosAsync()
{
    return impl::call_factory<Radio, Windows::Devices::Radios::IRadioStatics>([&](auto&& f) { return f.GetRadiosAsync(); });
}

inline hstring Radio::GetDeviceSelector()
{
    return impl::call_factory<Radio, Windows::Devices::Radios::IRadioStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> Radio::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Radio, Windows::Devices::Radios::IRadioStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> Radio::RequestAccessAsync()
{
    return impl::call_factory<Radio, Windows::Devices::Radios::IRadioStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Radios::IRadio> : winrt::impl::hash_base<winrt::Windows::Devices::Radios::IRadio> {};
template<> struct hash<winrt::Windows::Devices::Radios::IRadioStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Radios::IRadioStatics> {};
template<> struct hash<winrt::Windows::Devices::Radios::Radio> : winrt::impl::hash_base<winrt::Windows::Devices::Radios::Radio> {};

}
