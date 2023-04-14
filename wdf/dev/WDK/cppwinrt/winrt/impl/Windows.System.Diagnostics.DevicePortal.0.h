// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppService {

struct AppServiceConnection;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

enum class MessageWebSocketReceiveMode;
enum class SocketMessageType;
struct ServerMessageWebSocket;
struct ServerStreamWebSocket;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

struct HttpRequestMessage;
struct HttpResponseMessage;

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal {

enum class DevicePortalConnectionClosedReason : int32_t
{
    Unknown = 0,
    ResourceLimitsExceeded = 1,
    ProtocolError = 2,
    NotAuthorized = 3,
    UserNotPresent = 4,
    ServiceTerminated = 5,
};

struct IDevicePortalConnection;
struct IDevicePortalConnectionClosedEventArgs;
struct IDevicePortalConnectionRequestReceivedEventArgs;
struct IDevicePortalConnectionStatics;
struct IDevicePortalWebSocketConnection;
struct IDevicePortalWebSocketConnectionRequestReceivedEventArgs;
struct DevicePortalConnection;
struct DevicePortalConnectionClosedEventArgs;
struct DevicePortalConnectionRequestReceivedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection>{ using type = class_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs>{ using type = class_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason>{ using type = enum_category; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalConnection" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalConnectionClosedEventArgs" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalConnectionRequestReceivedEventArgs" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalConnectionStatics" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalWebSocketConnection" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.IDevicePortalWebSocketConnectionRequestReceivedEventArgs" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.DevicePortalConnection" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.DevicePortalConnectionClosedEventArgs" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.DevicePortalConnectionRequestReceivedEventArgs" }; };
template <> struct name<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason>{ static constexpr auto & value{ L"Windows.System.Diagnostics.DevicePortal.DevicePortalConnectionClosedReason" }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>{ static constexpr guid value{ 0x0F447F51,0x1198,0x4DA1,{ 0x8D,0x54,0xBD,0xEF,0x39,0x3E,0x09,0xB6 } }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>{ static constexpr guid value{ 0xFCF70E38,0x7032,0x428C,{ 0x9F,0x50,0x94,0x5C,0x15,0xA9,0xF0,0xCB } }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>{ static constexpr guid value{ 0x64DAE045,0x6FDA,0x4459,{ 0x9E,0xBD,0xEC,0xCE,0x22,0xE3,0x85,0x59 } }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>{ static constexpr guid value{ 0x4BBE31E7,0xE9B9,0x4645,{ 0x8F,0xED,0xA5,0x3E,0xEA,0x0E,0xDB,0xD6 } }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>{ static constexpr guid value{ 0x67657920,0xD65A,0x42F0,{ 0xAE,0xF4,0x78,0x78,0x08,0x09,0x8B,0x7B } }; };
template <> struct guid_storage<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>{ static constexpr guid value{ 0x79FDCABA,0x175C,0x4739,{ 0x9F,0x74,0xDD,0xA7,0x97,0xC3,0x5B,0x3F } }; };
template <> struct default_interface<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection>{ using type = Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection; };
template <> struct default_interface<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs>{ using type = Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs; };
template <> struct default_interface<Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs>{ using type = Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs; };

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RequestReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RequestReceived(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason* value) noexcept = 0;
};};

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForAppServiceConnection(void* appServiceConnection, void** value) noexcept = 0;
};};

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetServerMessageWebSocketForRequest(void* request, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetServerMessageWebSocketForRequest2(void* request, Windows::Networking::Sockets::SocketMessageType messageType, void* protocol, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetServerMessageWebSocketForRequest3(void* request, Windows::Networking::Sockets::SocketMessageType messageType, void* protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, Windows::Networking::Sockets::MessageWebSocketReceiveMode receiveMode, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetServerStreamWebSocketForRequest(void* request, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetServerStreamWebSocketForRequest2(void* request, void* protocol, uint32_t outboundBufferSizeInBytes, bool noDelay, void** result) noexcept = 0;
};};

template <> struct abi<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsWebSocketUpgradeRequest(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WebSocketProtocolsRequested(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection
{
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection, &impl::abi_t<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedEventArgs> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
    winrt::event_token RequestReceived(Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const;
    using RequestReceived_revoker = impl::event_revoker<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection, &impl::abi_t<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection>::remove_RequestReceived>;
    RequestReceived_revoker RequestReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::Diagnostics::DevicePortal::DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionRequestReceivedEventArgs> const& handler) const;
    void RequestReceived(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnection<D>; };

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionClosedEventArgs
{
    Windows::System::Diagnostics::DevicePortal::DevicePortalConnectionClosedReason Reason() const;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionClosedEventArgs<D>; };

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs
{
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Web::Http::HttpResponseMessage ResponseMessage() const;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionRequestReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionStatics
{
    Windows::System::Diagnostics::DevicePortal::DevicePortalConnection GetForAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) const;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionStatics> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalConnectionStatics<D>; };

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection
{
    Windows::Networking::Sockets::ServerMessageWebSocket GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request) const;
    Windows::Networking::Sockets::ServerMessageWebSocket GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol) const;
    Windows::Networking::Sockets::ServerMessageWebSocket GetServerMessageWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, Windows::Networking::Sockets::SocketMessageType const& messageType, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, uint32_t maxMessageSize, Windows::Networking::Sockets::MessageWebSocketReceiveMode const& receiveMode) const;
    Windows::Networking::Sockets::ServerStreamWebSocket GetServerStreamWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request) const;
    Windows::Networking::Sockets::ServerStreamWebSocket GetServerStreamWebSocketForRequest(Windows::Web::Http::HttpRequestMessage const& request, param::hstring const& protocol, uint32_t outboundBufferSizeInBytes, bool noDelay) const;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnection<D>; };

template <typename D>
struct consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs
{
    bool IsWebSocketUpgradeRequest() const;
    Windows::Foundation::Collections::IVectorView<hstring> WebSocketProtocolsRequested() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs> { template <typename D> using type = consume_Windows_System_Diagnostics_DevicePortal_IDevicePortalWebSocketConnectionRequestReceivedEventArgs<D>; };

}
