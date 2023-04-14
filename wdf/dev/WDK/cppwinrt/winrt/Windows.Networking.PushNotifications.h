// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Notifications.2.h"
#include "winrt/impl/Windows.Networking.PushNotifications.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::Uri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannel)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::ExpirationTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannel)->get_ExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannel)->Close());
}

template <typename D> winrt::event_token consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannel)->add_PushNotificationReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived_revoker consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PushNotificationReceived_revoker>(this, PushNotificationReceived(handler));
}

template <typename D> void consume_Windows_Networking_PushNotifications_IPushNotificationChannel<D>::PushNotificationReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannel)->remove_PushNotificationReceived(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForApplicationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForApplicationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForApplicationAsyncWithId(get_abi(applicationId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->CreatePushNotificationChannelForSecondaryTileAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2<D>::CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2)->CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(get_abi(appServerKey), get_abi(channelId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerForUser2<D>::CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(Windows::Storage::Streams::IBuffer const& appServerKey, param::hstring const& channelId, param::hstring const& appId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2)->CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsyncWithId(get_abi(appServerKey), get_abi(channelId), get_abi(appId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForApplicationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForApplicationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForApplicationAsyncWithId(get_abi(applicationId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics<D>::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics)->CreatePushNotificationChannelForSecondaryTileAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser consume_Windows_Networking_PushNotifications_IPushNotificationChannelManagerStatics3<D>::GetDefault() const
{
    Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->put_Cancel(value));
}

template <typename D> bool consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> Windows::Networking::PushNotifications::PushNotificationType consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::NotificationType() const
{
    Windows::Networking::PushNotifications::PushNotificationType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_NotificationType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::ToastNotification consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::ToastNotification() const
{
    Windows::UI::Notifications::ToastNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_ToastNotification(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::TileNotification consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::TileNotification() const
{
    Windows::UI::Notifications::TileNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_TileNotification(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Notifications::BadgeNotification consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::BadgeNotification() const
{
    Windows::UI::Notifications::BadgeNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_BadgeNotification(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::PushNotifications::RawNotification consume_Windows_Networking_PushNotifications_IPushNotificationReceivedEventArgs<D>::RawNotification() const
{
    Windows::Networking::PushNotifications::RawNotification value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs)->get_RawNotification(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_PushNotifications_IRawNotification<D>::Content() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IRawNotification)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_Networking_PushNotifications_IRawNotification2<D>::Headers() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IRawNotification2)->get_Headers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_PushNotifications_IRawNotification2<D>::ChannelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::PushNotifications::IRawNotification2)->get_ChannelId(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannel> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannel>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PushNotificationReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PushNotificationReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PushNotificationReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::PushNotifications::PushNotificationChannel, Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PushNotificationReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PushNotificationReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PushNotificationReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser>
{
    int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2>
{
    int32_t WINRT_CALL CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(void* appServerKey, void* channelId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), Windows::Storage::Streams::IBuffer const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&appServerKey), *reinterpret_cast<hstring const*>(&channelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsyncWithId(void* appServerKey, void* channelId, void* appId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), Windows::Storage::Streams::IBuffer const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreateRawPushNotificationChannelWithAlternateKeyForApplicationAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&appServerKey), *reinterpret_cast<hstring const*>(&channelId), *reinterpret_cast<hstring const*>(&appId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>
{
    int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePushNotificationChannelForApplicationAsyncWithId(void* applicationId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForApplicationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForApplicationAsync(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePushNotificationChannelForSecondaryTileAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePushNotificationChannelForSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel>>(this->shim().CreatePushNotificationChannelForSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser));
            *result = detach_from<Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> : produce_base<D, Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs>
{
    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NotificationType(Windows::Networking::PushNotifications::PushNotificationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationType, WINRT_WRAP(Windows::Networking::PushNotifications::PushNotificationType));
            *value = detach_from<Windows::Networking::PushNotifications::PushNotificationType>(this->shim().NotificationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToastNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToastNotification, WINRT_WRAP(Windows::UI::Notifications::ToastNotification));
            *value = detach_from<Windows::UI::Notifications::ToastNotification>(this->shim().ToastNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileNotification, WINRT_WRAP(Windows::UI::Notifications::TileNotification));
            *value = detach_from<Windows::UI::Notifications::TileNotification>(this->shim().TileNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BadgeNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BadgeNotification, WINRT_WRAP(Windows::UI::Notifications::BadgeNotification));
            *value = detach_from<Windows::UI::Notifications::BadgeNotification>(this->shim().BadgeNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawNotification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawNotification, WINRT_WRAP(Windows::Networking::PushNotifications::RawNotification));
            *value = detach_from<Windows::Networking::PushNotifications::RawNotification>(this->shim().RawNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IRawNotification> : produce_base<D, Windows::Networking::PushNotifications::IRawNotification>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::PushNotifications::IRawNotification2> : produce_base<D, Windows::Networking::PushNotifications::IRawNotification2>
{
    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ChannelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::PushNotifications {

inline Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> PushNotificationChannelManager::CreatePushNotificationChannelForApplicationAsync()
{
    return impl::call_factory<PushNotificationChannelManager, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>([&](auto&& f) { return f.CreatePushNotificationChannelForApplicationAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> PushNotificationChannelManager::CreatePushNotificationChannelForApplicationAsync(param::hstring const& applicationId)
{
    return impl::call_factory<PushNotificationChannelManager, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>([&](auto&& f) { return f.CreatePushNotificationChannelForApplicationAsync(applicationId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::PushNotifications::PushNotificationChannel> PushNotificationChannelManager::CreatePushNotificationChannelForSecondaryTileAsync(param::hstring const& tileId)
{
    return impl::call_factory<PushNotificationChannelManager, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics>([&](auto&& f) { return f.CreatePushNotificationChannelForSecondaryTileAsync(tileId); });
}

inline Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser PushNotificationChannelManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<PushNotificationChannelManager, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser PushNotificationChannelManager::GetDefault()
{
    return impl::call_factory<PushNotificationChannelManager, Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannel> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannel> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerForUser2> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics2> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationChannelManagerStatics3> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IPushNotificationReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IRawNotification> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IRawNotification> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::IRawNotification2> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::IRawNotification2> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannel> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::PushNotificationChannel> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManager> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManager> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::PushNotificationChannelManagerForUser> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::PushNotificationReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::PushNotifications::RawNotification> : winrt::impl::hash_base<winrt::Windows::Networking::PushNotifications::RawNotification> {};

}
