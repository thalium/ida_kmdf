// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.UI.Notifications.Management.2.h"
#include "winrt/Windows.UI.Notifications.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus> consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetAccessStatus() const
{
    Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->GetAccessStatus(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->add_NotificationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged_revoker consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NotificationChanged_revoker>(this, NotificationChanged(handler));
}

template <typename D> void consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::NotificationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->remove_NotificationChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::UserNotification>> consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetNotificationsAsync(Windows::UI::Notifications::NotificationKinds const& kinds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::UserNotification>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->GetNotificationsAsync(get_abi(kinds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Notifications::UserNotification consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::GetNotification(uint32_t notificationId) const
{
    Windows::UI::Notifications::UserNotification result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->GetNotification(notificationId, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::ClearNotifications() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->ClearNotifications());
}

template <typename D> void consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>::RemoveNotification(uint32_t notificationId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListener)->RemoveNotification(notificationId));
}

template <typename D> Windows::UI::Notifications::Management::UserNotificationListener consume_Windows_UI_Notifications_Management_IUserNotificationListenerStatics<D>::Current() const
{
    Windows::UI::Notifications::Management::UserNotificationListener value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Notifications::Management::IUserNotificationListenerStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Notifications::Management::IUserNotificationListener> : produce_base<D, Windows::UI::Notifications::Management::IUserNotificationListener>
{
    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccessStatus(Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccessStatus, WINRT_WRAP(Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus));
            *result = detach_from<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>(this->shim().GetAccessStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_NotificationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NotificationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NotificationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NotificationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NotificationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetNotificationsAsync(Windows::UI::Notifications::NotificationKinds kinds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNotificationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::UserNotification>>), Windows::UI::Notifications::NotificationKinds const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::UserNotification>>>(this->shim().GetNotificationsAsync(*reinterpret_cast<Windows::UI::Notifications::NotificationKinds const*>(&kinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNotification(uint32_t notificationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNotification, WINRT_WRAP(Windows::UI::Notifications::UserNotification), uint32_t);
            *result = detach_from<Windows::UI::Notifications::UserNotification>(this->shim().GetNotification(notificationId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearNotifications() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearNotifications, WINRT_WRAP(void));
            this->shim().ClearNotifications();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveNotification(uint32_t notificationId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveNotification, WINRT_WRAP(void), uint32_t);
            this->shim().RemoveNotification(notificationId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Notifications::Management::IUserNotificationListenerStatics> : produce_base<D, Windows::UI::Notifications::Management::IUserNotificationListenerStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::UI::Notifications::Management::UserNotificationListener));
            *value = detach_from<Windows::UI::Notifications::Management::UserNotificationListener>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management {

inline Windows::UI::Notifications::Management::UserNotificationListener UserNotificationListener::Current()
{
    return impl::call_factory<UserNotificationListener, Windows::UI::Notifications::Management::IUserNotificationListenerStatics>([&](auto&& f) { return f.Current(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Notifications::Management::IUserNotificationListener> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::Management::IUserNotificationListener> {};
template<> struct hash<winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::Management::IUserNotificationListenerStatics> {};
template<> struct hash<winrt::Windows::UI::Notifications::Management::UserNotificationListener> : winrt::impl::hash_base<winrt::Windows::UI::Notifications::Management::UserNotificationListener> {};

}
