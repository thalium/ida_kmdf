// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.System.Diagnostics.DevicePortal.2.h"
#include "winrt/Windows.System.Diagnostics.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed_revoker consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->add_RequestReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived_revoker consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RequestReceived_revoker>(this, RequestReceived(handler));
}

template <typename D> void consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>::RequestReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection)->remove_RequestReceived(get_abi(token)));
}

template <typename D> Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionClosedEventArgs<D>::Reason() const
{
    Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs<D>::ResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs)->get_ResponseMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::DevicePortal::DevicePortalConnection consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionStatics<D>::GetForAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) const
{
    Windows::System::Diagnostics::DevicePortal::DevicePortalConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics)->GetForAppServiceConnection(get_abi(appServiceConnection), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::ServerMessageWebSocket consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request) const
{
    Windows::Networking::Sockets::ServerMessageWebSocket result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest(get_abi(request), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::Sockets::ServerMessageWebSocket consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol) const
{
    Windows::Networking::Sockets::ServerMessageWebSocket result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest2(get_abi(request), get_abi(messageType), get_abi(protocol), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::Sockets::ServerMessageWebSocket consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, Windows::Networking::Sockets::MessageWebSocketReceiveMode const& receiveMode) const
{
    Windows::Networking::Sockets::ServerMessageWebSocket result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerMessageWebSocketForRequest3(get_abi(request), get_abi(messageType), get_abi(protocol), outboundBufferSizeInBytes, maxMessageSize, get_abi(receiveMode), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::Sockets::ServerStreamWebSocket consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerStreamWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request) const
{
    Windows::Networking::Sockets::ServerStreamWebSocket result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerStreamWebSocketForRequest(get_abi(request), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::Sockets::ServerStreamWebSocket consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>::GetServerStreamWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, bool noDelay) const
{
    Windows::Networking::Sockets::ServerStreamWebSocket result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection)->GetServerStreamWebSocketForRequest2(get_abi(request), get_abi(protocol), outboundBufferSizeInBytes, noDelay, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::IsWebSocketUpgradeRequest() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->get_IsWebSocketUpgradeRequest(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::WebSocketProtocolsRequested() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->get_WebSocketProtocolsRequested(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RequestReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RequestReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RequestReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RequestReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RequestReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason));
            *value = detach_from<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>
{
    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>
{
    int32_t WINRT_CALL GetForAppServiceConnection(void* appServiceConnection, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForAppServiceConnection, WINRT_WRAP(Windows::System::Diagnostics::DevicePortal::DevicePortalConnection), Windows::ApplicationModel::AppService::AppServiceConnection const&);
            *value = detach_from<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection>(this->shim().GetForAppServiceConnection(*reinterpret_cast<Windows::ApplicationModel::AppService::AppServiceConnection const*>(&appServiceConnection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>
{
    int32_t WINRT_CALL GetServerMessageWebSocketForRequest(void* request, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetServerMessageWebSocketForRequest, WINRT_WRAP(Windows::Networking::Sockets::ServerMessageWebSocket), Windows::Web::Http::HttpRequestMessage const&);
            *result = detach_from<Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetServerMessageWebSocketForRequest2(void* request, Windows::Networking::Sockets::SocketMessageType messageType, void* protocol, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetServerMessageWebSocketForRequest, WINRT_WRAP(Windows::Networking::Sockets::ServerMessageWebSocket), Windows::Web::Http::HttpRequestMessage const&, Windows::Networking::Sockets::SocketMessageType const&, hstring const&);
            *result = detach_from<Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<Windows::Networking::Sockets::SocketMessageType const*>(&messageType), *reinterpret_cast<hstring const*>(&protocol)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetServerMessageWebSocketForRequest3(void* request, Windows::Networking::Sockets::SocketMessageType messageType, void* protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, Windows::Networking::Sockets::MessageWebSocketReceiveMode receiveMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetServerMessageWebSocketForRequest, WINRT_WRAP(Windows::Networking::Sockets::ServerMessageWebSocket), Windows::Web::Http::HttpRequestMessage const&, Windows::Networking::Sockets::SocketMessageType const&, hstring const&, uint32_t, uint32_t, Windows::Networking::Sockets::MessageWebSocketReceiveMode const&);
            *result = detach_from<Windows::Networking::Sockets::ServerMessageWebSocket>(this->shim().GetServerMessageWebSocketForRequest(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<Windows::Networking::Sockets::SocketMessageType const*>(&messageType), *reinterpret_cast<hstring const*>(&protocol), outboundBufferSizeInBytes, maxMessageSize, *reinterpret_cast<Windows::Networking::Sockets::MessageWebSocketReceiveMode const*>(&receiveMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetServerStreamWebSocketForRequest(void* request, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetServerStreamWebSocketForRequest, WINRT_WRAP(Windows::Networking::Sockets::ServerStreamWebSocket), Windows::Web::Http::HttpRequestMessage const&);
            *result = detach_from<Windows::Networking::Sockets::ServerStreamWebSocket>(this->shim().GetServerStreamWebSocketForRequest(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetServerStreamWebSocketForRequest2(void* request, void* protocol, uint32_t outboundBufferSizeInBytes, bool noDelay, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetServerStreamWebSocketForRequest, WINRT_WRAP(Windows::Networking::Sockets::ServerStreamWebSocket), Windows::Web::Http::HttpRequestMessage const&, hstring const&, uint32_t, bool);
            *result = detach_from<Windows::Networking::Sockets::ServerStreamWebSocket>(this->shim().GetServerStreamWebSocketForRequest(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<hstring const*>(&protocol), outboundBufferSizeInBytes, noDelay));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> : produce_base<D, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>
{
    int32_t WINRT_CALL get_IsWebSocketUpgradeRequest(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWebSocketUpgradeRequest, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWebSocketUpgradeRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebSocketProtocolsRequested(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebSocketProtocolsRequested, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().WebSocketProtocolsRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal {

inline Windows::System::Diagnostics::DevicePortal::DevicePortalConnection DevicePortalConnection::GetForAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection)
{
    return impl::call_factory<DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>([&](auto&& f) { return f.GetForAppServiceConnection(appServiceConnection); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnection> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> {};

}
