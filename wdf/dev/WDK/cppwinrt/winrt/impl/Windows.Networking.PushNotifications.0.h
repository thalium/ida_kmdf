// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::UI::Notifications {

struct BadgeNotification;
struct TileNotification;
struct ToastNotification;

}

WINRT_EXPORT namespace winrt::Windows::Networking::PushNotifications {

enum class PushNotificationType : int32_t
{
    Toast = 0,
    Tile = 1,
    Badge = 2,
    Raw = 3,
    TileFlyout = 4,
};

struct IPushNotificationChannel;
struct IPushNotificationChannelManagerForUser;
struct IPushNotificationChannelManagerForUser2;
struct IPushNotificationChannelManagerStatics;
struct IPushNotificationChannelManagerStatics2;
struct IPushNotificationChannelManagerStatics3;
struct IPushNotificationReceivedEventArgs;
struct IRawNotification;
struct IRawNotification2;
struct PushNotificationChannel;
struct PushNotificationChannelManager;
struct PushNotificationChannelManagerForUser;
struct PushNotificationReceivedEventArgs;
struct RawNotification;

}

namespace winrt::impl {

template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannel>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IRawNotification>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::IRawNotification2>{ using type = interface_category; };
template <> struct category<Windows::Networking::PushNotifications::PushNotificationChannel>{ using type = class_category; };
template <> struct category<Windows::Networking::PushNotifications::PushNotificationChannelManager>{ using type = class_category; };
template <> struct category<Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>{ using type = class_category; };
template <> struct category<Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Networking::PushNotifications::RawNotification>{ using type = class_category; };
template <> struct category<Windows::Networking::PushNotifications::PushNotificationType>{ using type = enum_category; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannel>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannel" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannelManagerForUser" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannelManagerForUser2" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannelManagerStatics" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannelManagerStatics2" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationChannelManagerStatics3" }; };
template <> struct name<Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IPushNotificationReceivedEventArgs" }; };
template <> struct name<Windows::Networking::PushNotifications::IRawNotification>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IRawNotification" }; };
template <> struct name<Windows::Networking::PushNotifications::IRawNotification2>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.IRawNotification2" }; };
template <> struct name<Windows::Networking::PushNotifications::PushNotificationChannel>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.PushNotificationChannel" }; };
template <> struct name<Windows::Networking::PushNotifications::PushNotificationChannelManager>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.PushNotificationChannelManager" }; };
template <> struct name<Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.PushNotificationChannelManagerForUser" }; };
template <> struct name<Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.PushNotificationReceivedEventArgs" }; };
template <> struct name<Windows::Networking::PushNotifications::RawNotification>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.RawNotification" }; };
template <> struct name<Windows::Networking::PushNotifications::PushNotificationType>{ static constexpr auto & value{ L"Windows.Networking.PushNotifications.PushNotificationType" }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannel>{ static constexpr guid value{ 0x2B28102E,0xEF0B,0x4F39,{ 0x9B,0x8A,0xA3,0xC1,0x94,0xDE,0x70,0x81 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>{ static constexpr guid value{ 0xA4C45704,0x1182,0x42C7,{ 0x88,0x90,0xF5,0x63,0xC4,0x89,0x0D,0xC4 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>{ static constexpr guid value{ 0xC38B066A,0x7CC1,0x4DAC,{ 0x87,0xFD,0xBE,0x6E,0x92,0x04,0x14,0xA4 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>{ static constexpr guid value{ 0x8BAF9B65,0x77A1,0x4588,{ 0xBD,0x19,0x86,0x15,0x29,0xA9,0xDC,0xF0 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>{ static constexpr guid value{ 0xB444A65D,0xA7E9,0x4B28,{ 0x95,0x0E,0xF3,0x75,0xA9,0x07,0xF9,0xDF } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>{ static constexpr guid value{ 0x4701FEFE,0x0EDE,0x4A3F,{ 0xAE,0x78,0xBF,0xA4,0x71,0x49,0x69,0x25 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>{ static constexpr guid value{ 0xD1065E0C,0x36CD,0x484C,{ 0xB9,0x35,0x0A,0x99,0xB7,0x53,0xCF,0x00 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IRawNotification>{ static constexpr guid value{ 0x1A227281,0x3B79,0x42AC,{ 0x99,0x63,0x22,0xAB,0x00,0xD4,0xF0,0xB7 } }; };
template <> struct guid_storage<Windows::Networking::PushNotifications::IRawNotification2>{ static constexpr guid value{ 0xE6D0CF19,0x0C6F,0x4CDD,{ 0x94,0x24,0xEE,0xC5,0xBE,0x01,0x4D,0x26 } }; };
template <> struct default_interface<Windows::Networking::PushNotifications::PushNotificationChannel>{ using type = Windows::Networking::PushNotifications::IPushNotificationChannel; };
template <> struct default_interface<Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>{ using type = Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser; };
template <> struct default_interface<Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs>{ using type = Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs; };
template <> struct default_interface<Windows::Networking::PushNotifications::RawNotification>{ using type = Windows::Networking::PushNotifications::IRawNotification; };

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL Close() noexcept = 0;
    virtual int32_t WINRT_CALL add_PushNotificationReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PushNotificationReceived(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(void* appServerKey, void* channelId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsyncWithId(void* appServerKey, void* channelId, void* appId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Cancel(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cancel(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NotificationType(Windows::Networking::PushNotifications::PushNotificationType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ToastNotification(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TileNotification(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BadgeNotification(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawNotification(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IRawNotification>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Networking::PushNotifications::IRawNotification2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Headers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelId(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannel
{
    hstring Uri() const;
    Windows::Foundation::DateTime ExpirationTime() const;
    void Close() const;
    winrt::event_token PushNotificationReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const;
    using PushNotificationReceived_revoker = impl::event_revoker<Windows::Networking::PushNotifications::IPushNotificationChannel, &impl::abi_t<Windows::Networking::PushNotifications::IPushNotificationChannel>::remove_PushNotificationReceived>;
    PushNotificationReceived_revoker PushNotificationReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const;
    void PushNotificationReceived(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannel> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForApplicationAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const;
    Windows::System::User User() const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId, param::hstring const& appId) const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForApplicationAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const;
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics2
{
    Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics2<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics3
{
    Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser GetDefault() const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics3<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs
{
    void Cancel(bool value) const;
    bool Cancel() const;
    Windows::Networking::PushNotifications::PushNotificationType NotificationType() const;
    Windows::UI::Notifications::ToastNotification ToastNotification() const;
    Windows::UI::Notifications::TileNotification TileNotification() const;
    Windows::UI::Notifications::BadgeNotification BadgeNotification() const;
    Windows::Networking::PushNotifications::RawNotification RawNotification() const;
};
template <> struct consume<Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IRawNotification
{
    hstring Content() const;
};
template <> struct consume<Windows::Networking::PushNotifications::IRawNotification> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IRawNotification<D>; };

template <typename D>
struct consume_Windows_Networking_PushNotifications_IRawNotification2
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> Headers() const;
    hstring ChannelId() const;
};
template <> struct consume<Windows::Networking::PushNotifications::IRawNotification2> { template <typename D> using type = consume_Windows_Networking_PushNotifications_IRawNotification2<D>; };

}
