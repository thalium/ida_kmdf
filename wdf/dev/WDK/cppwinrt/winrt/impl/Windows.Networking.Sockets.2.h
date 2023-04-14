// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Background.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Networking.1.h"
#include "winrt/impl/Windows.Networking.Connectivity.1.h"
#include "winrt/impl/Windows.Security.Credentials.1.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Web.1.h"
#include "winrt/impl/Windows.Networking.Sockets.1.h"

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

struct BandwidthStatistics
{
    uint64_t OutboundBitsPerSecond;
    uint64_t InboundBitsPerSecond;
    uint64_t OutboundBitsPerSecondInstability;
    uint64_t InboundBitsPerSecondInstability;
    bool OutboundBandwidthPeaked;
    bool InboundBandwidthPeaked;
};

inline bool operator==(BandwidthStatistics const& left, BandwidthStatistics const& right) noexcept
{
    return left.OutboundBitsPerSecond == right.OutboundBitsPerSecond && left.InboundBitsPerSecond == right.InboundBitsPerSecond && left.OutboundBitsPerSecondInstability == right.OutboundBitsPerSecondInstability && left.InboundBitsPerSecondInstability == right.InboundBitsPerSecondInstability && left.OutboundBandwidthPeaked == right.OutboundBandwidthPeaked && left.InboundBandwidthPeaked == right.InboundBandwidthPeaked;
}

inline bool operator!=(BandwidthStatistics const& left, BandwidthStatistics const& right) noexcept
{
    return !(left == right);
}

struct RoundTripTimeStatistics
{
    uint32_t Variance;
    uint32_t Max;
    uint32_t Min;
    uint32_t Sum;
};

inline bool operator==(RoundTripTimeStatistics const& left, RoundTripTimeStatistics const& right) noexcept
{
    return left.Variance == right.Variance && left.Max == right.Max && left.Min == right.Min && left.Sum == right.Sum;
}

inline bool operator!=(RoundTripTimeStatistics const& left, RoundTripTimeStatistics const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

struct WINRT_EBO ControlChannelTrigger :
    Windows::Networking::Sockets::IControlChannelTrigger,
    impl::require<ControlChannelTrigger, Windows::Networking::Sockets::IControlChannelTrigger2>
{
    ControlChannelTrigger(std::nullptr_t) noexcept {}
    ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes);
    ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes, Windows::Networking::Sockets::ControlChannelTriggerResourceType const& resourceRequestType);
};

struct WINRT_EBO DatagramSocket :
    Windows::Networking::Sockets::IDatagramSocket,
    impl::require<DatagramSocket, Windows::Networking::Sockets::IDatagramSocket2, Windows::Networking::Sockets::IDatagramSocket3>
{
    DatagramSocket(std::nullptr_t) noexcept {}
    DatagramSocket();
    using impl::consume_t<DatagramSocket, Windows::Networking::Sockets::IDatagramSocket2>::BindServiceNameAsync;
    using Windows::Networking::Sockets::IDatagramSocket::BindServiceNameAsync;
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions);
};

struct WINRT_EBO DatagramSocketControl :
    Windows::Networking::Sockets::IDatagramSocketControl,
    impl::require<DatagramSocketControl, Windows::Networking::Sockets::IDatagramSocketControl2, Windows::Networking::Sockets::IDatagramSocketControl3>
{
    DatagramSocketControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DatagramSocketInformation :
    Windows::Networking::Sockets::IDatagramSocketInformation
{
    DatagramSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DatagramSocketMessageReceivedEventArgs :
    Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs
{
    DatagramSocketMessageReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MessageWebSocket :
    Windows::Networking::Sockets::IMessageWebSocket,
    impl::require<MessageWebSocket, Windows::Networking::Sockets::IMessageWebSocket2, Windows::Networking::Sockets::IMessageWebSocket3>
{
    MessageWebSocket(std::nullptr_t) noexcept {}
    MessageWebSocket();
};

struct WINRT_EBO MessageWebSocketControl :
    Windows::Networking::Sockets::IMessageWebSocketControl,
    impl::require<MessageWebSocketControl, Windows::Networking::Sockets::IMessageWebSocketControl2, Windows::Networking::Sockets::IWebSocketControl2>
{
    MessageWebSocketControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MessageWebSocketInformation :
    Windows::Networking::Sockets::IWebSocketInformation,
    impl::require<MessageWebSocketInformation, Windows::Networking::Sockets::IWebSocketInformation2>
{
    MessageWebSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MessageWebSocketMessageReceivedEventArgs :
    Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs,
    impl::require<MessageWebSocketMessageReceivedEventArgs, Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2>
{
    MessageWebSocketMessageReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ServerMessageWebSocket :
    Windows::Networking::Sockets::IServerMessageWebSocket
{
    ServerMessageWebSocket(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ServerMessageWebSocketControl :
    Windows::Networking::Sockets::IServerMessageWebSocketControl
{
    ServerMessageWebSocketControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ServerMessageWebSocketInformation :
    Windows::Networking::Sockets::IServerMessageWebSocketInformation
{
    ServerMessageWebSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ServerStreamWebSocket :
    Windows::Networking::Sockets::IServerStreamWebSocket
{
    ServerStreamWebSocket(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ServerStreamWebSocketInformation :
    Windows::Networking::Sockets::IServerStreamWebSocketInformation
{
    ServerStreamWebSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SocketActivityContext :
    Windows::Networking::Sockets::ISocketActivityContext
{
    SocketActivityContext(std::nullptr_t) noexcept {}
    SocketActivityContext(Windows::Storage::Streams::IBuffer const& data);
};

struct WINRT_EBO SocketActivityInformation :
    Windows::Networking::Sockets::ISocketActivityInformation
{
    SocketActivityInformation(std::nullptr_t) noexcept {}
    static Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation> AllSockets();
};

struct WINRT_EBO SocketActivityTriggerDetails :
    Windows::Networking::Sockets::ISocketActivityTriggerDetails
{
    SocketActivityTriggerDetails(std::nullptr_t) noexcept {}
};

struct SocketError
{
    SocketError() = delete;
    static Windows::Networking::Sockets::SocketErrorStatus GetStatus(int32_t hresult);
};

struct WINRT_EBO StreamSocket :
    Windows::Networking::Sockets::IStreamSocket,
    impl::require<StreamSocket, Windows::Networking::Sockets::IStreamSocket2, Windows::Networking::Sockets::IStreamSocket3>
{
    StreamSocket(std::nullptr_t) noexcept {}
    StreamSocket();
    using impl::consume_t<StreamSocket, Windows::Networking::Sockets::IStreamSocket2>::ConnectAsync;
    using Windows::Networking::Sockets::IStreamSocket::ConnectAsync;
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName);
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions);
};

struct WINRT_EBO StreamSocketControl :
    Windows::Networking::Sockets::IStreamSocketControl,
    impl::require<StreamSocketControl, Windows::Networking::Sockets::IStreamSocketControl2, Windows::Networking::Sockets::IStreamSocketControl3, Windows::Networking::Sockets::IStreamSocketControl4>
{
    StreamSocketControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamSocketInformation :
    Windows::Networking::Sockets::IStreamSocketInformation,
    impl::require<StreamSocketInformation, Windows::Networking::Sockets::IStreamSocketInformation2>
{
    StreamSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamSocketListener :
    Windows::Networking::Sockets::IStreamSocketListener,
    impl::require<StreamSocketListener, Windows::Networking::Sockets::IStreamSocketListener2, Windows::Networking::Sockets::IStreamSocketListener3>
{
    StreamSocketListener(std::nullptr_t) noexcept {}
    StreamSocketListener();
    using impl::consume_t<StreamSocketListener, Windows::Networking::Sockets::IStreamSocketListener2>::BindServiceNameAsync;
    using Windows::Networking::Sockets::IStreamSocketListener::BindServiceNameAsync;
};

struct WINRT_EBO StreamSocketListenerConnectionReceivedEventArgs :
    Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs
{
    StreamSocketListenerConnectionReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamSocketListenerControl :
    Windows::Networking::Sockets::IStreamSocketListenerControl,
    impl::require<StreamSocketListenerControl, Windows::Networking::Sockets::IStreamSocketListenerControl2>
{
    StreamSocketListenerControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamSocketListenerInformation :
    Windows::Networking::Sockets::IStreamSocketListenerInformation
{
    StreamSocketListenerInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamWebSocket :
    Windows::Networking::Sockets::IStreamWebSocket,
    impl::require<StreamWebSocket, Windows::Networking::Sockets::IStreamWebSocket2>
{
    StreamWebSocket(std::nullptr_t) noexcept {}
    StreamWebSocket();
};

struct WINRT_EBO StreamWebSocketControl :
    Windows::Networking::Sockets::IStreamWebSocketControl,
    impl::require<StreamWebSocketControl, Windows::Networking::Sockets::IStreamWebSocketControl2, Windows::Networking::Sockets::IWebSocketControl2>
{
    StreamWebSocketControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StreamWebSocketInformation :
    Windows::Networking::Sockets::IWebSocketInformation,
    impl::require<StreamWebSocketInformation, Windows::Networking::Sockets::IWebSocketInformation2>
{
    StreamWebSocketInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebSocketClosedEventArgs :
    Windows::Networking::Sockets::IWebSocketClosedEventArgs
{
    WebSocketClosedEventArgs(std::nullptr_t) noexcept {}
};

struct WebSocketError
{
    WebSocketError() = delete;
    static Windows::Web::WebErrorStatus GetStatus(int32_t hresult);
};

struct WINRT_EBO WebSocketKeepAlive :
    Windows::ApplicationModel::Background::IBackgroundTask
{
    WebSocketKeepAlive(std::nullptr_t) noexcept {}
    WebSocketKeepAlive();
};

struct WINRT_EBO WebSocketServerCustomValidationRequestedEventArgs :
    Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs
{
    WebSocketServerCustomValidationRequestedEventArgs(std::nullptr_t) noexcept {}
};

}
