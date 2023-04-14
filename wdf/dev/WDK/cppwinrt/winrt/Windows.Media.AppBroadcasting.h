// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Media.AppBroadcasting.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcasting() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->get_IsCurrentAppBroadcasting(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(Windows::Foundation::TypedEventHandler<Windows::Media::AppBroadcasting::AppBroadcastingMonitor, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->add_IsCurrentAppBroadcastingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged_revoker consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::AppBroadcasting::AppBroadcastingMonitor, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsCurrentAppBroadcastingChanged_revoker>(this, IsCurrentAppBroadcastingChanged(handler));
}

template <typename D> void consume_Windows_Media_AppBroadcasting_IAppBroadcastingMonitor<D>::IsCurrentAppBroadcastingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingMonitor)->remove_IsCurrentAppBroadcastingChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatus<D>::CanStartBroadcast() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatus)->get_CanStartBroadcast(&value));
    return value;
}

template <typename D> Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatus<D>::Details() const
{
    Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatus)->get_Details(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsAnyAppBroadcasting() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsAnyAppBroadcasting(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsCaptureResourceUnavailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsCaptureResourceUnavailable(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsGameStreamInProgress() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsGameStreamInProgress(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsGpuConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsGpuConstrained(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsAppInactive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsAppInactive(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsBlockedForApp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsBlockedForApp(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsDisabledByUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsDisabledByUser(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_AppBroadcasting_IAppBroadcastingStatusDetails<D>::IsDisabledBySystem() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails)->get_IsDisabledBySystem(&value));
    return value;
}

template <typename D> Windows::Media::AppBroadcasting::AppBroadcastingStatus consume_Windows_Media_AppBroadcasting_IAppBroadcastingUI<D>::GetStatus() const
{
    Windows::Media::AppBroadcasting::AppBroadcastingStatus result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingUI)->GetStatus(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_AppBroadcasting_IAppBroadcastingUI<D>::ShowBroadcastUI() const
{
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingUI)->ShowBroadcastUI());
}

template <typename D> Windows::Media::AppBroadcasting::AppBroadcastingUI consume_Windows_Media_AppBroadcasting_IAppBroadcastingUIStatics<D>::GetDefault() const
{
    Windows::Media::AppBroadcasting::AppBroadcastingUI result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::AppBroadcasting::AppBroadcastingUI consume_Windows_Media_AppBroadcasting_IAppBroadcastingUIStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Media::AppBroadcasting::AppBroadcastingUI result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Media::AppBroadcasting::IAppBroadcastingMonitor> : produce_base<D, Windows::Media::AppBroadcasting::IAppBroadcastingMonitor>
{
    int32_t WINRT_CALL get_IsCurrentAppBroadcasting(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAppBroadcasting, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentAppBroadcasting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsCurrentAppBroadcastingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAppBroadcastingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::AppBroadcasting::AppBroadcastingMonitor, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsCurrentAppBroadcastingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::AppBroadcasting::AppBroadcastingMonitor, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsCurrentAppBroadcastingChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsCurrentAppBroadcastingChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsCurrentAppBroadcastingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::AppBroadcasting::IAppBroadcastingStatus> : produce_base<D, Windows::Media::AppBroadcasting::IAppBroadcastingStatus>
{
    int32_t WINRT_CALL get_CanStartBroadcast(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanStartBroadcast, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanStartBroadcast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Details(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Details, WINRT_WRAP(Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails));
            *value = detach_from<Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails>(this->shim().Details());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails> : produce_base<D, Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails>
{
    int32_t WINRT_CALL get_IsAnyAppBroadcasting(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAnyAppBroadcasting, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAnyAppBroadcasting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCaptureResourceUnavailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCaptureResourceUnavailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCaptureResourceUnavailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGameStreamInProgress(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGameStreamInProgress, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGameStreamInProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGpuConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGpuConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAppInactive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppInactive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppInactive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBlockedForApp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBlockedForApp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBlockedForApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledByUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledByUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledBySystem(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledBySystem, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppBroadcasting::IAppBroadcastingUI> : produce_base<D, Windows::Media::AppBroadcasting::IAppBroadcastingUI>
{
    int32_t WINRT_CALL GetStatus(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Media::AppBroadcasting::AppBroadcastingStatus));
            *result = detach_from<Windows::Media::AppBroadcasting::AppBroadcastingStatus>(this->shim().GetStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowBroadcastUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowBroadcastUI, WINRT_WRAP(void));
            this->shim().ShowBroadcastUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics> : produce_base<D, Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Media::AppBroadcasting::AppBroadcastingUI));
            *result = detach_from<Windows::Media::AppBroadcasting::AppBroadcastingUI>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Media::AppBroadcasting::AppBroadcastingUI), Windows::System::User const&);
            *result = detach_from<Windows::Media::AppBroadcasting::AppBroadcastingUI>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::AppBroadcasting {

inline AppBroadcastingMonitor::AppBroadcastingMonitor() :
    AppBroadcastingMonitor(impl::call_factory<AppBroadcastingMonitor>([](auto&& f) { return f.template ActivateInstance<AppBroadcastingMonitor>(); }))
{}

inline Windows::Media::AppBroadcasting::AppBroadcastingUI AppBroadcastingUI::GetDefault()
{
    return impl::call_factory<AppBroadcastingUI, Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Media::AppBroadcasting::AppBroadcastingUI AppBroadcastingUI::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AppBroadcastingUI, Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics>([&](auto&& f) { return f.GetForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingMonitor> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatus> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingStatusDetails> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUI> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::IAppBroadcastingUIStatics> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::AppBroadcastingMonitor> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatus> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::AppBroadcastingStatusDetails> {};
template<> struct hash<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI> : winrt::impl::hash_base<winrt::Windows::Media::AppBroadcasting::AppBroadcastingUI> {};

}
