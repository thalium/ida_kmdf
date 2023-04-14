// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI::Notifications {

enum class NotificationKinds : unsigned;
struct UserNotification;
struct UserNotificationChangedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::UI::Notifications::Management {

enum class UserNotificationListenerAccessStatus : int32_t
{
    Unspecified = 0,
    Allowed = 1,
    Denied = 2,
};

struct IUserNotificationListener;
struct IUserNotificationListenerStatics;
struct UserNotificationListener;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Notifications::Management::IUserNotificationListener>{ using type = interface_category; };
template <> struct category<Windows::UI::Notifications::Management::IUserNotificationListenerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Notifications::Management::UserNotificationListener>{ using type = class_category; };
template <> struct category<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>{ using type = enum_category; };
template <> struct name<Windows::UI::Notifications::Management::IUserNotificationListener>{ static constexpr auto & value{ L"Windows.UI.Notifications.Management.IUserNotificationListener" }; };
template <> struct name<Windows::UI::Notifications::Management::IUserNotificationListenerStatics>{ static constexpr auto & value{ L"Windows.UI.Notifications.Management.IUserNotificationListenerStatics" }; };
template <> struct name<Windows::UI::Notifications::Management::UserNotificationListener>{ static constexpr auto & value{ L"Windows.UI.Notifications.Management.UserNotificationListener" }; };
template <> struct name<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus>{ static constexpr auto & value{ L"Windows.UI.Notifications.Management.UserNotificationListenerAccessStatus" }; };
template <> struct guid_storage<Windows::UI::Notifications::Management::IUserNotificationListener>{ static constexpr guid value{ 0x62553E41,0x8A06,0x4CEF,{ 0x82,0x15,0x60,0x33,0xA5,0xBE,0x4B,0x03 } }; };
template <> struct guid_storage<Windows::UI::Notifications::Management::IUserNotificationListenerStatics>{ static constexpr guid value{ 0xFF6123CF,0x4386,0x4AA3,{ 0xB7,0x3D,0xB8,0x04,0xE5,0xB6,0x3B,0x23 } }; };
template <> struct default_interface<Windows::UI::Notifications::Management::UserNotificationListener>{ using type = Windows::UI::Notifications::Management::IUserNotificationListener; };

template <> struct abi<Windows::UI::Notifications::Management::IUserNotificationListener>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAccessStatus(Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus* result) noexcept = 0;
    virtual int32_t WINRT_CALL add_NotificationChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NotificationChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetNotificationsAsync(Windows::UI::Notifications::NotificationKinds kinds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetNotification(uint32_t notificationId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ClearNotifications() noexcept = 0;
    virtual int32_t WINRT_CALL RemoveNotification(uint32_t notificationId) noexcept = 0;
};};

template <> struct abi<Windows::UI::Notifications::Management::IUserNotificationListenerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Notifications_Management_IUserNotificationListener
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus> RequestAccessAsync() const;
    Windows::UI::Notifications::Management::UserNotificationListenerAccessStatus GetAccessStatus() const;
    winrt::event_token NotificationChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const;
    using NotificationChanged_revoker = impl::event_revoker<Windows::UI::Notifications::Management::IUserNotificationListener, &impl::abi_t<Windows::UI::Notifications::Management::IUserNotificationListener>::remove_NotificationChanged>;
    NotificationChanged_revoker NotificationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Notifications::Management::UserNotificationListener, Windows::UI::Notifications::UserNotificationChangedEventArgs> const& handler) const;
    void NotificationChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::Notifications::UserNotification>> GetNotificationsAsync(Windows::UI::Notifications::NotificationKinds const& kinds) const;
    Windows::UI::Notifications::UserNotification GetNotification(uint32_t notificationId) const;
    void ClearNotifications() const;
    void RemoveNotification(uint32_t notificationId) const;
};
template <> struct consume<Windows::UI::Notifications::Management::IUserNotificationListener> { template <typename D> using type = consume_Windows_UI_Notifications_Management_IUserNotificationListener<D>; };

template <typename D>
struct consume_Windows_UI_Notifications_Management_IUserNotificationListenerStatics
{
    Windows::UI::Notifications::Management::UserNotificationListener Current() const;
};
template <> struct consume<Windows::UI::Notifications::Management::IUserNotificationListenerStatics> { template <typename D> using type = consume_Windows_UI_Notifications_Management_IUserNotificationListenerStatics<D>; };

}
