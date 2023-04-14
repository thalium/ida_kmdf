// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ControlChannelTriggerId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_ControlChannelTriggerId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ServerKeepAliveIntervalInMinutes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_ServerKeepAliveIntervalInMinutes(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::ServerKeepAliveIntervalInMinutes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->put_ServerKeepAliveIntervalInMinutes(value));
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::CurrentKeepAliveIntervalInMinutes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_CurrentKeepAliveIntervalInMinutes(&value));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::TransportObject() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_TransportObject(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Background::IBackgroundTrigger consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::KeepAliveTrigger() const
{
    Windows::ApplicationModel::Background::IBackgroundTrigger trigger{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_KeepAliveTrigger(put_abi(trigger)));
    return trigger;
}

template <typename D> Windows::ApplicationModel::Background::IBackgroundTrigger consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::PushNotificationTrigger() const
{
    Windows::ApplicationModel::Background::IBackgroundTrigger trigger{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->get_PushNotificationTrigger(put_abi(trigger)));
    return trigger;
}

template <typename D> void consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::UsingTransport(Windows::Foundation::IInspectable const& transport) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->UsingTransport(get_abi(transport)));
}

template <typename D> Windows::Networking::Sockets::ControlChannelTriggerStatus consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::WaitForPushEnabled() const
{
    Windows::Networking::Sockets::ControlChannelTriggerStatus channelTriggerStatus{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->WaitForPushEnabled(put_abi(channelTriggerStatus)));
    return channelTriggerStatus;
}

template <typename D> void consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::DecreaseNetworkKeepAliveInterval() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->DecreaseNetworkKeepAliveInterval());
}

template <typename D> void consume_Windows_Networking_Sockets_IControlChannelTrigger<D>::FlushTransport() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger)->FlushTransport());
}

template <typename D> bool consume_Windows_Networking_Sockets_IControlChannelTrigger2<D>::IsWakeFromLowPowerSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTrigger2)->get_IsWakeFromLowPowerSupported(&value));
    return value;
}

template <typename D> Windows::Networking::Sockets::ControlChannelTrigger consume_Windows_Networking_Sockets_IControlChannelTriggerEventDetails<D>::ControlChannelTrigger() const
{
    Windows::Networking::Sockets::ControlChannelTrigger value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerEventDetails)->get_ControlChannelTrigger(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::ControlChannelTrigger consume_Windows_Networking_Sockets_IControlChannelTriggerFactory<D>::CreateControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes) const
{
    Windows::Networking::Sockets::ControlChannelTrigger notificationChannel{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerFactory)->CreateControlChannelTrigger(get_abi(channelId), serverKeepAliveIntervalInMinutes, put_abi(notificationChannel)));
    return notificationChannel;
}

template <typename D> Windows::Networking::Sockets::ControlChannelTrigger consume_Windows_Networking_Sockets_IControlChannelTriggerFactory<D>::CreateControlChannelTriggerEx(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes, Windows::Networking::Sockets::ControlChannelTriggerResourceType const& resourceRequestType) const
{
    Windows::Networking::Sockets::ControlChannelTrigger notificationChannel{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerFactory)->CreateControlChannelTriggerEx(get_abi(channelId), serverKeepAliveIntervalInMinutes, get_abi(resourceRequestType), put_abi(notificationChannel)));
    return notificationChannel;
}

template <typename D> Windows::Networking::Sockets::ControlChannelTriggerResetReason consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::ResetReason() const
{
    Windows::Networking::Sockets::ControlChannelTriggerResetReason value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_ResetReason(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::HardwareSlotReset() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_HardwareSlotReset(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Sockets_IControlChannelTriggerResetEventDetails<D>::SoftwareSlotReset() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails)->get_SoftwareSlotReset(&value));
    return value;
}

template <typename D> Windows::Networking::Sockets::DatagramSocketControl consume_Windows_Networking_Sockets_IDatagramSocket<D>::Control() const
{
    Windows::Networking::Sockets::DatagramSocketControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::DatagramSocketInformation consume_Windows_Networking_Sockets_IDatagramSocket<D>::Information() const
{
    Windows::Networking::Sockets::DatagramSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Networking_Sockets_IDatagramSocket<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket<D>::ConnectAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->ConnectAsync(get_abi(remoteHostName), get_abi(remoteServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket<D>::ConnectAsync(Windows::Networking::EndpointPair const& endpointPair) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->ConnectWithEndpointPairAsync(get_abi(endpointPair), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket<D>::BindServiceNameAsync(param::hstring const& localServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->BindServiceNameAsync(get_abi(localServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket<D>::BindEndpointAsync(Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->BindEndpointAsync(get_abi(localHostName), get_abi(localServiceName), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket<D>::JoinMulticastGroup(Windows::Networking::HostName const& host) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->JoinMulticastGroup(get_abi(host)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream> consume_Windows_Networking_Sockets_IDatagramSocket<D>::GetOutputStreamAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->GetOutputStreamAsync(get_abi(remoteHostName), get_abi(remoteServiceName), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream> consume_Windows_Networking_Sockets_IDatagramSocket<D>::GetOutputStreamAsync(Windows::Networking::EndpointPair const& endpointPair) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->GetOutputStreamWithEndpointPairAsync(get_abi(endpointPair), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::DatagramSocket, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->add_MessageReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::DatagramSocket, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket<D>::MessageReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket)->remove_MessageReceived(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket2<D>::BindServiceNameAsync(param::hstring const& localServiceName, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket2)->BindServiceNameAndAdapterAsync(get_abi(localServiceName), get_abi(adapter), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IDatagramSocket3<D>::CancelIOAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->CancelIOAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->EnableTransferOwnership(get_abi(taskId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->EnableTransferOwnershipWithConnectedStandbyAction(get_abi(taskId), get_abi(connectedStandbyAction)));
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnership(get_abi(socketId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId, Windows::Networking::Sockets::SocketActivityContext const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnershipWithContext(get_abi(socketId), get_abi(data)));
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocket3<D>::TransferOwnership(param::hstring const& socketId, Windows::Networking::Sockets::SocketActivityContext const& data, Windows::Foundation::TimeSpan const& keepAliveTime) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocket3)->TransferOwnershipWithContextAndKeepAliveTime(get_abi(socketId), get_abi(data), get_abi(keepAliveTime)));
}

template <typename D> Windows::Networking::Sockets::SocketQualityOfService consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::QualityOfService() const
{
    Windows::Networking::Sockets::SocketQualityOfService value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl)->get_QualityOfService(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::QualityOfService(Windows::Networking::Sockets::SocketQualityOfService const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl)->put_QualityOfService(get_abi(value)));
}

template <typename D> uint8_t consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::OutboundUnicastHopLimit() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl)->get_OutboundUnicastHopLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocketControl<D>::OutboundUnicastHopLimit(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl)->put_OutboundUnicastHopLimit(value));
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::InboundBufferSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl2)->get_InboundBufferSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::InboundBufferSizeInBytes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl2)->put_InboundBufferSizeInBytes(value));
}

template <typename D> bool consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::DontFragment() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl2)->get_DontFragment(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocketControl2<D>::DontFragment(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl2)->put_DontFragment(value));
}

template <typename D> bool consume_Windows_Networking_Sockets_IDatagramSocketControl3<D>::MulticastOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl3)->get_MulticastOnly(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IDatagramSocketControl3<D>::MulticastOnly(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketControl3)->put_MulticastOnly(value));
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketInformation)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::LocalPort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketInformation)->get_LocalPort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::RemoteAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketInformation)->get_RemoteAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IDatagramSocketInformation<D>::RemotePort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketInformation)->get_RemotePort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::RemoteAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_RemoteAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::RemotePort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_RemotePort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::DataReader consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::GetDataReader() const
{
    Windows::Storage::Streams::DataReader dataReader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->GetDataReader(put_abi(dataReader)));
    return dataReader;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_Sockets_IDatagramSocketMessageReceivedEventArgs<D>::GetDataStream() const
{
    Windows::Storage::Streams::IInputStream inputStream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs)->GetDataStream(put_abi(inputStream)));
    return inputStream;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> consume_Windows_Networking_Sockets_IDatagramSocketStatics<D>::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketStatics)->GetEndpointPairsAsync(get_abi(remoteHostName), get_abi(remoteServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> consume_Windows_Networking_Sockets_IDatagramSocketStatics<D>::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IDatagramSocketStatics)->GetEndpointPairsWithSortOptionsAsync(get_abi(remoteHostName), get_abi(remoteServiceName), get_abi(sortOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::Sockets::MessageWebSocketControl consume_Windows_Networking_Sockets_IMessageWebSocket<D>::Control() const
{
    Windows::Networking::Sockets::MessageWebSocketControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::MessageWebSocketInformation consume_Windows_Networking_Sockets_IMessageWebSocket<D>::Information() const
{
    Windows::Networking::Sockets::MessageWebSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket)->add_MessageReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocket<D>::MessageReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket)->remove_MessageReceived(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket2)->add_ServerCustomValidationRequested(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested_revoker consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, ServerCustomValidationRequested_revoker>(this, ServerCustomValidationRequested(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocket2<D>::ServerCustomValidationRequested(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket2)->remove_ServerCustomValidationRequested(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> consume_Windows_Networking_Sockets_IMessageWebSocket3<D>::SendNonfinalFrameAsync(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket3)->SendNonfinalFrameAsync(get_abi(data), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> consume_Windows_Networking_Sockets_IMessageWebSocket3<D>::SendFinalFrameAsync(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocket3)->SendFinalFrameAsync(get_abi(data), put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MaxMessageSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl)->get_MaxMessageSize(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MaxMessageSize(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl)->put_MaxMessageSize(value));
}

template <typename D> Windows::Networking::Sockets::SocketMessageType consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MessageType() const
{
    Windows::Networking::Sockets::SocketMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocketControl<D>::MessageType(Windows::Networking::Sockets::SocketMessageType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl)->put_MessageType(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::DesiredUnsolicitedPongInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->get_DesiredUnsolicitedPongInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->put_DesiredUnsolicitedPongInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ActualUnsolicitedPongInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ActualUnsolicitedPongInterval(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::MessageWebSocketReceiveMode consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ReceiveMode() const
{
    Windows::Networking::Sockets::MessageWebSocketReceiveMode value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ReceiveMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ReceiveMode(Windows::Networking::Sockets::MessageWebSocketReceiveMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->put_ReceiveMode(get_abi(value)));
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ClientCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->get_ClientCertificate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IMessageWebSocketControl2<D>::ClientCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketControl2)->put_ClientCertificate(get_abi(value)));
}

template <typename D> Windows::Networking::Sockets::SocketMessageType consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::MessageType() const
{
    Windows::Networking::Sockets::SocketMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::DataReader consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::GetDataReader() const
{
    Windows::Storage::Streams::DataReader dataReader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->GetDataReader(put_abi(dataReader)));
    return dataReader;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs<D>::GetDataStream() const
{
    Windows::Storage::Streams::IInputStream inputStream{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs)->GetDataStream(put_abi(inputStream)));
    return inputStream;
}

template <typename D> bool consume_Windows_Networking_Sockets_IMessageWebSocketMessageReceivedEventArgs2<D>::IsMessageComplete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2)->get_IsMessageComplete(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->add_MessageReceived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived_revoker consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MessageReceived_revoker>(this, MessageReceived(value));
}

template <typename D> void consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::MessageReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->remove_MessageReceived(get_abi(token)));
}

template <typename D> Windows::Networking::Sockets::ServerMessageWebSocketControl consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Control() const
{
    Windows::Networking::Sockets::ServerMessageWebSocketControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::ServerMessageWebSocketInformation consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Information() const
{
    Windows::Networking::Sockets::ServerMessageWebSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->add_Closed(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(value));
}

template <typename D> void consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->remove_Closed(get_abi(token)));
}

template <typename D> void consume_Windows_Networking_Sockets_IServerMessageWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocket)->CloseWithStatus(code, get_abi(reason)));
}

template <typename D> Windows::Networking::Sockets::SocketMessageType consume_Windows_Networking_Sockets_IServerMessageWebSocketControl<D>::MessageType() const
{
    Windows::Networking::Sockets::SocketMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocketControl)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IServerMessageWebSocketControl<D>::MessageType(Windows::Networking::Sockets::SocketMessageType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocketControl)->put_MessageType(get_abi(value)));
}

template <typename D> Windows::Networking::Sockets::BandwidthStatistics consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::BandwidthStatistics() const
{
    Windows::Networking::Sockets::BandwidthStatistics value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::Protocol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_Protocol(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IServerMessageWebSocketInformation<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerMessageWebSocketInformation)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::ServerStreamWebSocketInformation consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Information() const
{
    Windows::Networking::Sockets::ServerStreamWebSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerStreamWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->add_Closed(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerStreamWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(value));
}

template <typename D> void consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->remove_Closed(get_abi(token)));
}

template <typename D> void consume_Windows_Networking_Sockets_IServerStreamWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocket)->CloseWithStatus(code, get_abi(reason)));
}

template <typename D> Windows::Networking::Sockets::BandwidthStatistics consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::BandwidthStatistics() const
{
    Windows::Networking::Sockets::BandwidthStatistics value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::Protocol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_Protocol(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IServerStreamWebSocketInformation<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IServerStreamWebSocketInformation)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Sockets_ISocketActivityContext<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityContext)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketActivityContext consume_Windows_Networking_Sockets_ISocketActivityContextFactory<D>::Create(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Networking::Sockets::SocketActivityContext context{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityContextFactory)->Create(get_abi(data), put_abi(context)));
    return context;
}

template <typename D> winrt::guid consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::TaskId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketActivityKind consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::SocketKind() const
{
    Windows::Networking::Sockets::SocketActivityKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_SocketKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketActivityContext consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::Context() const
{
    Windows::Networking::Sockets::SocketActivityContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_Context(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::DatagramSocket consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::DatagramSocket() const
{
    Windows::Networking::Sockets::DatagramSocket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_DatagramSocket(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocket consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::StreamSocket() const
{
    Windows::Networking::Sockets::StreamSocket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_StreamSocket(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocketListener consume_Windows_Networking_Sockets_ISocketActivityInformation<D>::StreamSocketListener() const
{
    Windows::Networking::Sockets::StreamSocketListener value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformation)->get_StreamSocketListener(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation> consume_Windows_Networking_Sockets_ISocketActivityInformationStatics<D>::AllSockets() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation> sockets{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityInformationStatics)->get_AllSockets(put_abi(sockets)));
    return sockets;
}

template <typename D> Windows::Networking::Sockets::SocketActivityTriggerReason consume_Windows_Networking_Sockets_ISocketActivityTriggerDetails<D>::Reason() const
{
    Windows::Networking::Sockets::SocketActivityTriggerReason value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityTriggerDetails)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketActivityInformation consume_Windows_Networking_Sockets_ISocketActivityTriggerDetails<D>::SocketInformation() const
{
    Windows::Networking::Sockets::SocketActivityInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketActivityTriggerDetails)->get_SocketInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketErrorStatus consume_Windows_Networking_Sockets_ISocketErrorStatics<D>::GetStatus(int32_t hresult) const
{
    Windows::Networking::Sockets::SocketErrorStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::ISocketErrorStatics)->GetStatus(hresult, put_abi(status)));
    return status;
}

template <typename D> Windows::Networking::Sockets::StreamSocketControl consume_Windows_Networking_Sockets_IStreamSocket<D>::Control() const
{
    Windows::Networking::Sockets::StreamSocketControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocketInformation consume_Windows_Networking_Sockets_IStreamSocket<D>::Information() const
{
    Windows::Networking::Sockets::StreamSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_Sockets_IStreamSocket<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Networking_Sockets_IStreamSocket<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(Windows::Networking::EndpointPair const& endpointPair) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->ConnectWithEndpointPairAsync(get_abi(endpointPair), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->ConnectAsync(get_abi(remoteHostName), get_abi(remoteServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(Windows::Networking::EndpointPair const& endpointPair, Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->ConnectWithEndpointPairAndProtectionLevelAsync(get_abi(endpointPair), get_abi(protectionLevel), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket<D>::ConnectAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->ConnectWithProtectionLevelAsync(get_abi(remoteHostName), get_abi(remoteServiceName), get_abi(protectionLevel), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket<D>::UpgradeToSslAsync(Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, Windows::Networking::HostName const& validationHostName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket)->UpgradeToSslAsync(get_abi(protectionLevel), get_abi(validationHostName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket2<D>::ConnectAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket2)->ConnectWithProtectionLevelAndAdapterAsync(get_abi(remoteHostName), get_abi(remoteServiceName), get_abi(protectionLevel), get_abi(adapter), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocket3<D>::CancelIOAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->CancelIOAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->EnableTransferOwnership(get_abi(taskId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocket3<D>::EnableTransferOwnership(winrt::guid const& taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->EnableTransferOwnershipWithConnectedStandbyAction(get_abi(taskId), get_abi(connectedStandbyAction)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->TransferOwnership(get_abi(socketId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId, Windows::Networking::Sockets::SocketActivityContext const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->TransferOwnershipWithContext(get_abi(socketId), get_abi(data)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocket3<D>::TransferOwnership(param::hstring const& socketId, Windows::Networking::Sockets::SocketActivityContext const& data, Windows::Foundation::TimeSpan const& keepAliveTime) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocket3)->TransferOwnershipWithContextAndKeepAliveTime(get_abi(socketId), get_abi(data), get_abi(keepAliveTime)));
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamSocketControl<D>::NoDelay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->get_NoDelay(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl<D>::NoDelay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->put_NoDelay(value));
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamSocketControl<D>::KeepAlive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->get_KeepAlive(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl<D>::KeepAlive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->put_KeepAlive(value));
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundBufferSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->get_OutboundBufferSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundBufferSizeInBytes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->put_OutboundBufferSizeInBytes(value));
}

template <typename D> Windows::Networking::Sockets::SocketQualityOfService consume_Windows_Networking_Sockets_IStreamSocketControl<D>::QualityOfService() const
{
    Windows::Networking::Sockets::SocketQualityOfService value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->get_QualityOfService(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl<D>::QualityOfService(Windows::Networking::Sockets::SocketQualityOfService const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->put_QualityOfService(get_abi(value)));
}

template <typename D> uint8_t consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundUnicastHopLimit() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->get_OutboundUnicastHopLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl<D>::OutboundUnicastHopLimit(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl)->put_OutboundUnicastHopLimit(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Networking_Sockets_IStreamSocketControl2<D>::IgnorableServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl2)->get_IgnorableServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::SerializeConnectionAttempts() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl3)->get_SerializeConnectionAttempts(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::SerializeConnectionAttempts(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl3)->put_SerializeConnectionAttempts(value));
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::ClientCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl3)->get_ClientCertificate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl3<D>::ClientCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl3)->put_ClientCertificate(get_abi(value)));
}

template <typename D> Windows::Networking::Sockets::SocketProtectionLevel consume_Windows_Networking_Sockets_IStreamSocketControl4<D>::MinProtectionLevel() const
{
    Windows::Networking::Sockets::SocketProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl4)->get_MinProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketControl4<D>::MinProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketControl4)->put_MinProtectionLevel(get_abi(value)));
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::LocalPort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_LocalPort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteHostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteHostName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemoteServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_RemoteServiceName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RemotePort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_RemotePort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::RoundTripTimeStatistics consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::RoundTripTimeStatistics() const
{
    Windows::Networking::Sockets::RoundTripTimeStatistics value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_RoundTripTimeStatistics(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::BandwidthStatistics consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::BandwidthStatistics() const
{
    Windows::Networking::Sockets::BandwidthStatistics value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_BandwidthStatistics(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketProtectionLevel consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::ProtectionLevel() const
{
    Windows::Networking::Sockets::SocketProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_ProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Sockets_IStreamSocketInformation<D>::SessionKey() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation)->get_SessionKey(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketSslErrorSeverity consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificateErrorSeverity() const
{
    Windows::Networking::Sockets::SocketSslErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificateErrorSeverity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerCertificate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_Networking_Sockets_IStreamSocketInformation2<D>::ServerIntermediateCertificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketInformation2)->get_ServerIntermediateCertificates(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocketListenerControl consume_Windows_Networking_Sockets_IStreamSocketListener<D>::Control() const
{
    Windows::Networking::Sockets::StreamSocketListenerControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocketListenerInformation consume_Windows_Networking_Sockets_IStreamSocketListener<D>::Information() const
{
    Windows::Networking::Sockets::StreamSocketListenerInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocketListener<D>::BindServiceNameAsync(param::hstring const& localServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->BindServiceNameAsync(get_abi(localServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocketListener<D>::BindEndpointAsync(Windows::Networking::HostName const& localHostName, param::hstring const& localServiceName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->BindEndpointAsync(get_abi(localHostName), get_abi(localServiceName), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamSocketListener, Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->add_ConnectionReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived_revoker consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamSocketListener, Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, ConnectionReceived_revoker>(this, ConnectionReceived(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListener<D>::ConnectionReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener)->remove_ConnectionReceived(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocketListener2<D>::BindServiceNameAsync(param::hstring const& localServiceName, Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener2)->BindServiceNameWithProtectionLevelAsync(get_abi(localServiceName), get_abi(protectionLevel), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocketListener2<D>::BindServiceNameAsync(param::hstring const& localServiceName, Windows::Networking::Sockets::SocketProtectionLevel const& protectionLevel, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener2)->BindServiceNameWithProtectionLevelAndAdapterAsync(get_abi(localServiceName), get_abi(protectionLevel), get_abi(adapter), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::CancelIOAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener3)->CancelIOAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::EnableTransferOwnership(winrt::guid const& taskId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener3)->EnableTransferOwnership(get_abi(taskId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::EnableTransferOwnership(winrt::guid const& taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const& connectedStandbyAction) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener3)->EnableTransferOwnershipWithConnectedStandbyAction(get_abi(taskId), get_abi(connectedStandbyAction)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::TransferOwnership(param::hstring const& socketId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener3)->TransferOwnership(get_abi(socketId)));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListener3<D>::TransferOwnership(param::hstring const& socketId, Windows::Networking::Sockets::SocketActivityContext const& data) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListener3)->TransferOwnershipWithContext(get_abi(socketId), get_abi(data)));
}

template <typename D> Windows::Networking::Sockets::StreamSocket consume_Windows_Networking_Sockets_IStreamSocketListenerConnectionReceivedEventArgs<D>::Socket() const
{
    Windows::Networking::Sockets::StreamSocket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs)->get_Socket(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketQualityOfService consume_Windows_Networking_Sockets_IStreamSocketListenerControl<D>::QualityOfService() const
{
    Windows::Networking::Sockets::SocketQualityOfService value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl)->get_QualityOfService(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListenerControl<D>::QualityOfService(Windows::Networking::Sockets::SocketQualityOfService const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl)->put_QualityOfService(get_abi(value)));
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::NoDelay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_NoDelay(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::NoDelay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_NoDelay(value));
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::KeepAlive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_KeepAlive(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::KeepAlive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_KeepAlive(value));
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundBufferSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_OutboundBufferSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundBufferSizeInBytes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_OutboundBufferSizeInBytes(value));
}

template <typename D> uint8_t consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundUnicastHopLimit() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->get_OutboundUnicastHopLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamSocketListenerControl2<D>::OutboundUnicastHopLimit(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerControl2)->put_OutboundUnicastHopLimit(value));
}

template <typename D> hstring consume_Windows_Networking_Sockets_IStreamSocketListenerInformation<D>::LocalPort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketListenerInformation)->get_LocalPort(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> consume_Windows_Networking_Sockets_IStreamSocketStatics<D>::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketStatics)->GetEndpointPairsAsync(get_abi(remoteHostName), get_abi(remoteServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> consume_Windows_Networking_Sockets_IStreamSocketStatics<D>::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamSocketStatics)->GetEndpointPairsWithSortOptionsAsync(get_abi(remoteHostName), get_abi(remoteServiceName), get_abi(sortOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::Sockets::StreamWebSocketControl consume_Windows_Networking_Sockets_IStreamWebSocket<D>::Control() const
{
    Windows::Networking::Sockets::StreamWebSocketControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocket)->get_Control(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamWebSocketInformation consume_Windows_Networking_Sockets_IStreamWebSocket<D>::Information() const
{
    Windows::Networking::Sockets::StreamWebSocketInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocket)->get_Information(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Networking_Sockets_IStreamWebSocket<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocket)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocket2)->add_ServerCustomValidationRequested(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested_revoker consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, ServerCustomValidationRequested_revoker>(this, ServerCustomValidationRequested(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamWebSocket2<D>::ServerCustomValidationRequested(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocket2)->remove_ServerCustomValidationRequested(get_abi(eventCookie)));
}

template <typename D> bool consume_Windows_Networking_Sockets_IStreamWebSocketControl<D>::NoDelay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl)->get_NoDelay(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamWebSocketControl<D>::NoDelay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl)->put_NoDelay(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::DesiredUnsolicitedPongInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl2)->get_DesiredUnsolicitedPongInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl2)->put_DesiredUnsolicitedPongInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ActualUnsolicitedPongInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl2)->get_ActualUnsolicitedPongInterval(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ClientCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl2)->get_ClientCertificate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IStreamWebSocketControl2<D>::ClientCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IStreamWebSocketControl2)->put_ClientCertificate(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Networking_Sockets_IWebSocket<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_Sockets_IWebSocket<D>::ConnectAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->ConnectAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocket<D>::SetRequestHeader(param::hstring const& headerName, param::hstring const& headerValue) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->SetRequestHeader(get_abi(headerName), get_abi(headerValue)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::IWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->add_Closed(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Sockets_IWebSocket<D>::Closed_revoker consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::IWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(eventHandler));
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocket<D>::Closed(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->remove_Closed(get_abi(eventCookie)));
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocket<D>::Close(uint16_t code, param::hstring const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocket)->CloseWithStatus(code, get_abi(reason)));
}

template <typename D> uint16_t consume_Windows_Networking_Sockets_IWebSocketClosedEventArgs<D>::Code() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketClosedEventArgs)->get_Code(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IWebSocketClosedEventArgs<D>::Reason() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketClosedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Sockets_IWebSocketControl<D>::OutboundBufferSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->get_OutboundBufferSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocketControl<D>::OutboundBufferSizeInBytes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->put_OutboundBufferSizeInBytes(value));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Networking_Sockets_IWebSocketControl<D>::ServerCredential() const
{
    Windows::Security::Credentials::PasswordCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->get_ServerCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocketControl<D>::ServerCredential(Windows::Security::Credentials::PasswordCredential const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->put_ServerCredential(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Networking_Sockets_IWebSocketControl<D>::ProxyCredential() const
{
    Windows::Security::Credentials::PasswordCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->get_ProxyCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocketControl<D>::ProxyCredential(Windows::Security::Credentials::PasswordCredential const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->put_ProxyCredential(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Networking_Sockets_IWebSocketControl<D>::SupportedProtocols() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl)->get_SupportedProtocols(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Networking_Sockets_IWebSocketControl2<D>::IgnorableServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketControl2)->get_IgnorableServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::WebErrorStatus consume_Windows_Networking_Sockets_IWebSocketErrorStatics<D>::GetStatus(int32_t hresult) const
{
    Windows::Web::WebErrorStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketErrorStatics)->GetStatus(hresult, put_abi(status)));
    return status;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Sockets_IWebSocketInformation<D>::LocalAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation)->get_LocalAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::BandwidthStatistics consume_Windows_Networking_Sockets_IWebSocketInformation<D>::BandwidthStatistics() const
{
    Windows::Networking::Sockets::BandwidthStatistics value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation)->get_BandwidthStatistics(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Sockets_IWebSocketInformation<D>::Protocol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation)->get_Protocol(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificate(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketSslErrorSeverity consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificateErrorSeverity() const
{
    Windows::Networking::Sockets::SocketSslErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificateErrorSeverity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_Networking_Sockets_IWebSocketInformation2<D>::ServerIntermediateCertificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketInformation2)->get_ServerIntermediateCertificates(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificate(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketSslErrorSeverity consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificateErrorSeverity() const
{
    Windows::Networking::Sockets::SocketSslErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificateErrorSeverity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::ServerIntermediateCertificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->get_ServerIntermediateCertificates(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::Reject() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->Reject());
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Networking_Sockets_IWebSocketServerCustomValidationRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Networking::Sockets::IControlChannelTrigger> : produce_base<D, Windows::Networking::Sockets::IControlChannelTrigger>
{
    int32_t WINRT_CALL get_ControlChannelTriggerId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlChannelTriggerId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ControlChannelTriggerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerKeepAliveIntervalInMinutes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerKeepAliveIntervalInMinutes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ServerKeepAliveIntervalInMinutes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServerKeepAliveIntervalInMinutes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerKeepAliveIntervalInMinutes, WINRT_WRAP(void), uint32_t);
            this->shim().ServerKeepAliveIntervalInMinutes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentKeepAliveIntervalInMinutes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentKeepAliveIntervalInMinutes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CurrentKeepAliveIntervalInMinutes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportObject(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportObject, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().TransportObject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepAliveTrigger(void** trigger) noexcept final
    {
        try
        {
            *trigger = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepAliveTrigger, WINRT_WRAP(Windows::ApplicationModel::Background::IBackgroundTrigger));
            *trigger = detach_from<Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().KeepAliveTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PushNotificationTrigger(void** trigger) noexcept final
    {
        try
        {
            *trigger = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PushNotificationTrigger, WINRT_WRAP(Windows::ApplicationModel::Background::IBackgroundTrigger));
            *trigger = detach_from<Windows::ApplicationModel::Background::IBackgroundTrigger>(this->shim().PushNotificationTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UsingTransport(void* transport) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsingTransport, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().UsingTransport(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&transport));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForPushEnabled(Windows::Networking::Sockets::ControlChannelTriggerStatus* channelTriggerStatus) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForPushEnabled, WINRT_WRAP(Windows::Networking::Sockets::ControlChannelTriggerStatus));
            *channelTriggerStatus = detach_from<Windows::Networking::Sockets::ControlChannelTriggerStatus>(this->shim().WaitForPushEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecreaseNetworkKeepAliveInterval() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecreaseNetworkKeepAliveInterval, WINRT_WRAP(void));
            this->shim().DecreaseNetworkKeepAliveInterval();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FlushTransport() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlushTransport, WINRT_WRAP(void));
            this->shim().FlushTransport();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IControlChannelTrigger2> : produce_base<D, Windows::Networking::Sockets::IControlChannelTrigger2>
{
    int32_t WINRT_CALL get_IsWakeFromLowPowerSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWakeFromLowPowerSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWakeFromLowPowerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IControlChannelTriggerEventDetails> : produce_base<D, Windows::Networking::Sockets::IControlChannelTriggerEventDetails>
{
    int32_t WINRT_CALL get_ControlChannelTrigger(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlChannelTrigger, WINRT_WRAP(Windows::Networking::Sockets::ControlChannelTrigger));
            *value = detach_from<Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().ControlChannelTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IControlChannelTriggerFactory> : produce_base<D, Windows::Networking::Sockets::IControlChannelTriggerFactory>
{
    int32_t WINRT_CALL CreateControlChannelTrigger(void* channelId, uint32_t serverKeepAliveIntervalInMinutes, void** notificationChannel) noexcept final
    {
        try
        {
            *notificationChannel = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateControlChannelTrigger, WINRT_WRAP(Windows::Networking::Sockets::ControlChannelTrigger), hstring const&, uint32_t);
            *notificationChannel = detach_from<Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().CreateControlChannelTrigger(*reinterpret_cast<hstring const*>(&channelId), serverKeepAliveIntervalInMinutes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateControlChannelTriggerEx(void* channelId, uint32_t serverKeepAliveIntervalInMinutes, Windows::Networking::Sockets::ControlChannelTriggerResourceType resourceRequestType, void** notificationChannel) noexcept final
    {
        try
        {
            *notificationChannel = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateControlChannelTriggerEx, WINRT_WRAP(Windows::Networking::Sockets::ControlChannelTrigger), hstring const&, uint32_t, Windows::Networking::Sockets::ControlChannelTriggerResourceType const&);
            *notificationChannel = detach_from<Windows::Networking::Sockets::ControlChannelTrigger>(this->shim().CreateControlChannelTriggerEx(*reinterpret_cast<hstring const*>(&channelId), serverKeepAliveIntervalInMinutes, *reinterpret_cast<Windows::Networking::Sockets::ControlChannelTriggerResourceType const*>(&resourceRequestType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails> : produce_base<D, Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails>
{
    int32_t WINRT_CALL get_ResetReason(Windows::Networking::Sockets::ControlChannelTriggerResetReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetReason, WINRT_WRAP(Windows::Networking::Sockets::ControlChannelTriggerResetReason));
            *value = detach_from<Windows::Networking::Sockets::ControlChannelTriggerResetReason>(this->shim().ResetReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareSlotReset(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareSlotReset, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HardwareSlotReset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoftwareSlotReset(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareSlotReset, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SoftwareSlotReset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocket> : produce_base<D, Windows::Networking::Sockets::IDatagramSocket>
{
    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::DatagramSocketControl));
            *value = detach_from<Windows::Networking::Sockets::DatagramSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::DatagramSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::DatagramSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithEndpointPairAsync(void* endpointPair, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::EndpointPair const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindServiceNameAsync(void* localServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindServiceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindEndpointAsync(void* localHostName, void* localServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindEndpointAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindEndpointAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL JoinMulticastGroup(void* host) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JoinMulticastGroup, WINRT_WRAP(void), Windows::Networking::HostName const&);
            this->shim().JoinMulticastGroup(*reinterpret_cast<Windows::Networking::HostName const*>(&host));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOutputStreamAsync(void* remoteHostName, void* remoteServiceName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOutputStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream>), Windows::Networking::HostName const, hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream>>(this->shim().GetOutputStreamAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOutputStreamWithEndpointPairAsync(void* endpointPair, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOutputStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream>), Windows::Networking::EndpointPair const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IOutputStream>>(this->shim().GetOutputStreamAsync(*reinterpret_cast<Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::DatagramSocket, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::DatagramSocket, Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocket2> : produce_base<D, Windows::Networking::Sockets::IDatagramSocket2>
{
    int32_t WINRT_CALL BindServiceNameAndAdapterAsync(void* localServiceName, void* adapter, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindServiceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Networking::Connectivity::NetworkAdapter const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocket3> : produce_base<D, Windows::Networking::Sockets::IDatagramSocket3>
{
    int32_t WINRT_CALL CancelIOAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelIOAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnership(winrt::guid taskId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction connectedStandbyAction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnership(void* socketId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnershipWithContext(void* socketId, void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&, Windows::Networking::Sockets::SocketActivityContext const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnershipWithContextAndKeepAliveTime(void* socketId, void* data, Windows::Foundation::TimeSpan keepAliveTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&, Windows::Networking::Sockets::SocketActivityContext const&, Windows::Foundation::TimeSpan const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityContext const*>(&data), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&keepAliveTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketControl> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketControl>
{
    int32_t WINRT_CALL get_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(Windows::Networking::Sockets::SocketQualityOfService));
            *value = detach_from<Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(void), Windows::Networking::Sockets::SocketQualityOfService const&);
            this->shim().QualityOfService(*reinterpret_cast<Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundUnicastHopLimit(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundUnicastHopLimit(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(void), uint8_t);
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketControl2> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketControl2>
{
    int32_t WINRT_CALL get_InboundBufferSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBufferSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().InboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InboundBufferSizeInBytes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBufferSizeInBytes, WINRT_WRAP(void), uint32_t);
            this->shim().InboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DontFragment(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DontFragment, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DontFragment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DontFragment(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DontFragment, WINRT_WRAP(void), bool);
            this->shim().DontFragment(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketControl3> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketControl3>
{
    int32_t WINRT_CALL get_MulticastOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MulticastOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().MulticastOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MulticastOnly(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MulticastOnly, WINRT_WRAP(void), bool);
            this->shim().MulticastOnly(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketInformation> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketInformation>
{
    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalPort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalPort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemotePort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemotePort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs>
{
    int32_t WINRT_CALL get_RemoteAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemotePort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemotePort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataReader(void** dataReader) noexcept final
    {
        try
        {
            *dataReader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataReader, WINRT_WRAP(Windows::Storage::Streams::DataReader));
            *dataReader = detach_from<Windows::Storage::Streams::DataReader>(this->shim().GetDataReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataStream(void** inputStream) noexcept final
    {
        try
        {
            *inputStream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *inputStream = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().GetDataStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IDatagramSocketStatics> : produce_base<D, Windows::Networking::Sockets::IDatagramSocketStatics>
{
    int32_t WINRT_CALL GetEndpointPairsAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEndpointPairsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEndpointPairsWithSortOptionsAsync(void* remoteHostName, void* remoteServiceName, Windows::Networking::HostNameSortOptions sortOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEndpointPairsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>), Windows::Networking::HostName const, hstring const, Windows::Networking::HostNameSortOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<Windows::Networking::HostNameSortOptions const*>(&sortOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocket> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocket>
{
    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::MessageWebSocketControl));
            *value = detach_from<Windows::Networking::Sockets::MessageWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::MessageWebSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::MessageWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MessageReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocket2> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocket2>
{
    int32_t WINRT_CALL add_ServerCustomValidationRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCustomValidationRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ServerCustomValidationRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::MessageWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServerCustomValidationRequested(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServerCustomValidationRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocket3> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocket3>
{
    int32_t WINRT_CALL SendNonfinalFrameAsync(void* data, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendNonfinalFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SendNonfinalFrameAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendFinalFrameAsync(void* data, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendFinalFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint32_t, uint32_t>>(this->shim().SendFinalFrameAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocketControl> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocketControl>
{
    int32_t WINRT_CALL get_MaxMessageSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessageSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxMessageSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxMessageSize(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessageSize, WINRT_WRAP(void), uint32_t);
            this->shim().MaxMessageSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageType(Windows::Networking::Sockets::SocketMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Networking::Sockets::SocketMessageType));
            *value = detach_from<Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MessageType(Windows::Networking::Sockets::SocketMessageType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(void), Windows::Networking::Sockets::SocketMessageType const&);
            this->shim().MessageType(*reinterpret_cast<Windows::Networking::Sockets::SocketMessageType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocketControl2> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocketControl2>
{
    int32_t WINRT_CALL get_DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredUnsolicitedPongInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DesiredUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredUnsolicitedPongInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DesiredUnsolicitedPongInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualUnsolicitedPongInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualUnsolicitedPongInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ActualUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceiveMode(Windows::Networking::Sockets::MessageWebSocketReceiveMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceiveMode, WINRT_WRAP(Windows::Networking::Sockets::MessageWebSocketReceiveMode));
            *value = detach_from<Windows::Networking::Sockets::MessageWebSocketReceiveMode>(this->shim().ReceiveMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReceiveMode(Windows::Networking::Sockets::MessageWebSocketReceiveMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceiveMode, WINRT_WRAP(void), Windows::Networking::Sockets::MessageWebSocketReceiveMode const&);
            this->shim().ReceiveMode(*reinterpret_cast<Windows::Networking::Sockets::MessageWebSocketReceiveMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClientCertificate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(void), Windows::Security::Cryptography::Certificates::Certificate const&);
            this->shim().ClientCertificate(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs>
{
    int32_t WINRT_CALL get_MessageType(Windows::Networking::Sockets::SocketMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Networking::Sockets::SocketMessageType));
            *value = detach_from<Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataReader(void** dataReader) noexcept final
    {
        try
        {
            *dataReader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataReader, WINRT_WRAP(Windows::Storage::Streams::DataReader));
            *dataReader = detach_from<Windows::Storage::Streams::DataReader>(this->shim().GetDataReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataStream(void** inputStream) noexcept final
    {
        try
        {
            *inputStream = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *inputStream = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().GetDataStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2> : produce_base<D, Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2>
{
    int32_t WINRT_CALL get_IsMessageComplete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMessageComplete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMessageComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IServerMessageWebSocket> : produce_base<D, Windows::Networking::Sockets::IServerMessageWebSocket>
{
    int32_t WINRT_CALL add_MessageReceived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::ServerMessageWebSocketControl));
            *value = detach_from<Windows::Networking::Sockets::ServerMessageWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::ServerMessageWebSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::ServerMessageWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerMessageWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&value)));
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

    int32_t WINRT_CALL CloseWithStatus(uint16_t code, void* reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), uint16_t, hstring const&);
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IServerMessageWebSocketControl> : produce_base<D, Windows::Networking::Sockets::IServerMessageWebSocketControl>
{
    int32_t WINRT_CALL get_MessageType(Windows::Networking::Sockets::SocketMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(Windows::Networking::Sockets::SocketMessageType));
            *value = detach_from<Windows::Networking::Sockets::SocketMessageType>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MessageType(Windows::Networking::Sockets::SocketMessageType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(void), Windows::Networking::Sockets::SocketMessageType const&);
            this->shim().MessageType(*reinterpret_cast<Windows::Networking::Sockets::SocketMessageType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IServerMessageWebSocketInformation> : produce_base<D, Windows::Networking::Sockets::IServerMessageWebSocketInformation>
{
    int32_t WINRT_CALL get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthStatistics, WINRT_WRAP(Windows::Networking::Sockets::BandwidthStatistics));
            *value = detach_from<Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Protocol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Protocol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IServerStreamWebSocket> : produce_base<D, Windows::Networking::Sockets::IServerStreamWebSocket>
{
    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::ServerStreamWebSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::ServerStreamWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerStreamWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::ServerStreamWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&value)));
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

    int32_t WINRT_CALL CloseWithStatus(uint16_t code, void* reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), uint16_t, hstring const&);
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IServerStreamWebSocketInformation> : produce_base<D, Windows::Networking::Sockets::IServerStreamWebSocketInformation>
{
    int32_t WINRT_CALL get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthStatistics, WINRT_WRAP(Windows::Networking::Sockets::BandwidthStatistics));
            *value = detach_from<Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Protocol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Protocol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketActivityContext> : produce_base<D, Windows::Networking::Sockets::ISocketActivityContext>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketActivityContextFactory> : produce_base<D, Windows::Networking::Sockets::ISocketActivityContextFactory>
{
    int32_t WINRT_CALL Create(void* data, void** context) noexcept final
    {
        try
        {
            *context = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Networking::Sockets::SocketActivityContext), Windows::Storage::Streams::IBuffer const&);
            *context = detach_from<Windows::Networking::Sockets::SocketActivityContext>(this->shim().Create(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketActivityInformation> : produce_base<D, Windows::Networking::Sockets::ISocketActivityInformation>
{
    int32_t WINRT_CALL get_TaskId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TaskId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SocketKind(Windows::Networking::Sockets::SocketActivityKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SocketKind, WINRT_WRAP(Windows::Networking::Sockets::SocketActivityKind));
            *value = detach_from<Windows::Networking::Sockets::SocketActivityKind>(this->shim().SocketKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Context(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(Windows::Networking::Sockets::SocketActivityContext));
            *value = detach_from<Windows::Networking::Sockets::SocketActivityContext>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DatagramSocket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DatagramSocket, WINRT_WRAP(Windows::Networking::Sockets::DatagramSocket));
            *value = detach_from<Windows::Networking::Sockets::DatagramSocket>(this->shim().DatagramSocket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamSocket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamSocket, WINRT_WRAP(Windows::Networking::Sockets::StreamSocket));
            *value = detach_from<Windows::Networking::Sockets::StreamSocket>(this->shim().StreamSocket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamSocketListener(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamSocketListener, WINRT_WRAP(Windows::Networking::Sockets::StreamSocketListener));
            *value = detach_from<Windows::Networking::Sockets::StreamSocketListener>(this->shim().StreamSocketListener());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketActivityInformationStatics> : produce_base<D, Windows::Networking::Sockets::ISocketActivityInformationStatics>
{
    int32_t WINRT_CALL get_AllSockets(void** sockets) noexcept final
    {
        try
        {
            *sockets = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllSockets, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation>));
            *sockets = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation>>(this->shim().AllSockets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketActivityTriggerDetails> : produce_base<D, Windows::Networking::Sockets::ISocketActivityTriggerDetails>
{
    int32_t WINRT_CALL get_Reason(Windows::Networking::Sockets::SocketActivityTriggerReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Networking::Sockets::SocketActivityTriggerReason));
            *value = detach_from<Windows::Networking::Sockets::SocketActivityTriggerReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SocketInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SocketInformation, WINRT_WRAP(Windows::Networking::Sockets::SocketActivityInformation));
            *value = detach_from<Windows::Networking::Sockets::SocketActivityInformation>(this->shim().SocketInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::ISocketErrorStatics> : produce_base<D, Windows::Networking::Sockets::ISocketErrorStatics>
{
    int32_t WINRT_CALL GetStatus(int32_t hresult, Windows::Networking::Sockets::SocketErrorStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Networking::Sockets::SocketErrorStatus), int32_t);
            *status = detach_from<Windows::Networking::Sockets::SocketErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocket> : produce_base<D, Windows::Networking::Sockets::IStreamSocket>
{
    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::StreamSocketControl));
            *value = detach_from<Windows::Networking::Sockets::StreamSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::StreamSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::StreamSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithEndpointPairAsync(void* endpointPair, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::EndpointPair const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::EndpointPair const*>(&endpointPair)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithEndpointPairAndProtectionLevelAsync(void* endpointPair, Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::EndpointPair const, Windows::Networking::Sockets::SocketProtectionLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::EndpointPair const*>(&endpointPair), *reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithProtectionLevelAsync(void* remoteHostName, void* remoteServiceName, Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const, Windows::Networking::Sockets::SocketProtectionLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpgradeToSslAsync(Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void* validationHostName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpgradeToSslAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::Sockets::SocketProtectionLevel const, Windows::Networking::HostName const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpgradeToSslAsync(*reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<Windows::Networking::HostName const*>(&validationHostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocket2> : produce_base<D, Windows::Networking::Sockets::IStreamSocket2>
{
    int32_t WINRT_CALL ConnectWithProtectionLevelAndAdapterAsync(void* remoteHostName, void* remoteServiceName, Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void* adapter, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const, Windows::Networking::Sockets::SocketProtectionLevel const, Windows::Networking::Connectivity::NetworkAdapter const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocket3> : produce_base<D, Windows::Networking::Sockets::IStreamSocket3>
{
    int32_t WINRT_CALL CancelIOAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelIOAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnership(winrt::guid taskId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction connectedStandbyAction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnership(void* socketId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnershipWithContext(void* socketId, void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&, Windows::Networking::Sockets::SocketActivityContext const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnershipWithContextAndKeepAliveTime(void* socketId, void* data, Windows::Foundation::TimeSpan keepAliveTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&, Windows::Networking::Sockets::SocketActivityContext const&, Windows::Foundation::TimeSpan const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityContext const*>(&data), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&keepAliveTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketControl> : produce_base<D, Windows::Networking::Sockets::IStreamSocketControl>
{
    int32_t WINRT_CALL get_NoDelay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NoDelay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(void), bool);
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepAlive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepAlive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().KeepAlive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeepAlive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepAlive, WINRT_WRAP(void), bool);
            this->shim().KeepAlive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundBufferSizeInBytes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(void), uint32_t);
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(Windows::Networking::Sockets::SocketQualityOfService));
            *value = detach_from<Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(void), Windows::Networking::Sockets::SocketQualityOfService const&);
            this->shim().QualityOfService(*reinterpret_cast<Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundUnicastHopLimit(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundUnicastHopLimit(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(void), uint8_t);
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketControl2> : produce_base<D, Windows::Networking::Sockets::IStreamSocketControl2>
{
    int32_t WINRT_CALL get_IgnorableServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnorableServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().IgnorableServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketControl3> : produce_base<D, Windows::Networking::Sockets::IStreamSocketControl3>
{
    int32_t WINRT_CALL get_SerializeConnectionAttempts(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerializeConnectionAttempts, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SerializeConnectionAttempts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SerializeConnectionAttempts(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerializeConnectionAttempts, WINRT_WRAP(void), bool);
            this->shim().SerializeConnectionAttempts(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClientCertificate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(void), Windows::Security::Cryptography::Certificates::Certificate const&);
            this->shim().ClientCertificate(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketControl4> : produce_base<D, Windows::Networking::Sockets::IStreamSocketControl4>
{
    int32_t WINRT_CALL get_MinProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinProtectionLevel, WINRT_WRAP(Windows::Networking::Sockets::SocketProtectionLevel));
            *value = detach_from<Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().MinProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinProtectionLevel, WINRT_WRAP(void), Windows::Networking::Sockets::SocketProtectionLevel const&);
            this->shim().MinProtectionLevel(*reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketInformation> : produce_base<D, Windows::Networking::Sockets::IStreamSocketInformation>
{
    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalPort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalPort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteHostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteHostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().RemoteHostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().RemoteAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteServiceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteServiceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemotePort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemotePort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemotePort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoundTripTimeStatistics(struct struct_Windows_Networking_Sockets_RoundTripTimeStatistics* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoundTripTimeStatistics, WINRT_WRAP(Windows::Networking::Sockets::RoundTripTimeStatistics));
            *value = detach_from<Windows::Networking::Sockets::RoundTripTimeStatistics>(this->shim().RoundTripTimeStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthStatistics, WINRT_WRAP(Windows::Networking::Sockets::BandwidthStatistics));
            *value = detach_from<Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(Windows::Networking::Sockets::SocketProtectionLevel));
            *value = detach_from<Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SessionKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketInformation2> : produce_base<D, Windows::Networking::Sockets::IStreamSocketInformation2>
{
    int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrorSeverity, WINRT_WRAP(Windows::Networking::Sockets::SocketSslErrorSeverity));
            *value = detach_from<Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerIntermediateCertificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListener> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListener>
{
    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::StreamSocketListenerControl));
            *value = detach_from<Windows::Networking::Sockets::StreamSocketListenerControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::StreamSocketListenerInformation));
            *value = detach_from<Windows::Networking::Sockets::StreamSocketListenerInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindServiceNameAsync(void* localServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindServiceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindEndpointAsync(void* localHostName, void* localServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindEndpointAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindEndpointAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ConnectionReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamSocketListener, Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ConnectionReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamSocketListener, Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListener2> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListener2>
{
    int32_t WINRT_CALL BindServiceNameWithProtectionLevelAsync(void* localServiceName, Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindServiceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Networking::Sockets::SocketProtectionLevel const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BindServiceNameWithProtectionLevelAndAdapterAsync(void* localServiceName, Windows::Networking::Sockets::SocketProtectionLevel protectionLevel, void* adapter, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindServiceNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Networking::Sockets::SocketProtectionLevel const, Windows::Networking::Connectivity::NetworkAdapter const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().BindServiceNameAsync(*reinterpret_cast<hstring const*>(&localServiceName), *reinterpret_cast<Windows::Networking::Sockets::SocketProtectionLevel const*>(&protectionLevel), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListener3> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListener3>
{
    int32_t WINRT_CALL CancelIOAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelIOAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CancelIOAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnership(winrt::guid taskId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableTransferOwnershipWithConnectedStandbyAction(winrt::guid taskId, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction connectedStandbyAction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTransferOwnership, WINRT_WRAP(void), winrt::guid const&, Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const&);
            this->shim().EnableTransferOwnership(*reinterpret_cast<winrt::guid const*>(&taskId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityConnectedStandbyAction const*>(&connectedStandbyAction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnership(void* socketId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferOwnershipWithContext(void* socketId, void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferOwnership, WINRT_WRAP(void), hstring const&, Windows::Networking::Sockets::SocketActivityContext const&);
            this->shim().TransferOwnership(*reinterpret_cast<hstring const*>(&socketId), *reinterpret_cast<Windows::Networking::Sockets::SocketActivityContext const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs>
{
    int32_t WINRT_CALL get_Socket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Socket, WINRT_WRAP(Windows::Networking::Sockets::StreamSocket));
            *value = detach_from<Windows::Networking::Sockets::StreamSocket>(this->shim().Socket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListenerControl> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListenerControl>
{
    int32_t WINRT_CALL get_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(Windows::Networking::Sockets::SocketQualityOfService));
            *value = detach_from<Windows::Networking::Sockets::SocketQualityOfService>(this->shim().QualityOfService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_QualityOfService(Windows::Networking::Sockets::SocketQualityOfService value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QualityOfService, WINRT_WRAP(void), Windows::Networking::Sockets::SocketQualityOfService const&);
            this->shim().QualityOfService(*reinterpret_cast<Windows::Networking::Sockets::SocketQualityOfService const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListenerControl2> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListenerControl2>
{
    int32_t WINRT_CALL get_NoDelay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NoDelay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(void), bool);
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepAlive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepAlive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().KeepAlive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeepAlive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepAlive, WINRT_WRAP(void), bool);
            this->shim().KeepAlive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundBufferSizeInBytes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(void), uint32_t);
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundUnicastHopLimit(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().OutboundUnicastHopLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundUnicastHopLimit(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundUnicastHopLimit, WINRT_WRAP(void), uint8_t);
            this->shim().OutboundUnicastHopLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketListenerInformation> : produce_base<D, Windows::Networking::Sockets::IStreamSocketListenerInformation>
{
    int32_t WINRT_CALL get_LocalPort(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalPort, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamSocketStatics> : produce_base<D, Windows::Networking::Sockets::IStreamSocketStatics>
{
    int32_t WINRT_CALL GetEndpointPairsAsync(void* remoteHostName, void* remoteServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEndpointPairsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>), Windows::Networking::HostName const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEndpointPairsWithSortOptionsAsync(void* remoteHostName, void* remoteServiceName, Windows::Networking::HostNameSortOptions sortOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEndpointPairsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>), Windows::Networking::HostName const, hstring const, Windows::Networking::HostNameSortOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>>(this->shim().GetEndpointPairsAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remoteServiceName), *reinterpret_cast<Windows::Networking::HostNameSortOptions const*>(&sortOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamWebSocket> : produce_base<D, Windows::Networking::Sockets::IStreamWebSocket>
{
    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::Networking::Sockets::StreamWebSocketControl));
            *value = detach_from<Windows::Networking::Sockets::StreamWebSocketControl>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Information(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Information, WINRT_WRAP(Windows::Networking::Sockets::StreamWebSocketInformation));
            *value = detach_from<Windows::Networking::Sockets::StreamWebSocketInformation>(this->shim().Information());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamWebSocket2> : produce_base<D, Windows::Networking::Sockets::IStreamWebSocket2>
{
    int32_t WINRT_CALL add_ServerCustomValidationRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCustomValidationRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ServerCustomValidationRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::StreamWebSocket, Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServerCustomValidationRequested(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServerCustomValidationRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServerCustomValidationRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamWebSocketControl> : produce_base<D, Windows::Networking::Sockets::IStreamWebSocketControl>
{
    int32_t WINRT_CALL get_NoDelay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NoDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NoDelay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoDelay, WINRT_WRAP(void), bool);
            this->shim().NoDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IStreamWebSocketControl2> : produce_base<D, Windows::Networking::Sockets::IStreamWebSocketControl2>
{
    int32_t WINRT_CALL get_DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredUnsolicitedPongInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DesiredUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredUnsolicitedPongInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredUnsolicitedPongInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DesiredUnsolicitedPongInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualUnsolicitedPongInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualUnsolicitedPongInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ActualUnsolicitedPongInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ClientCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClientCertificate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCertificate, WINRT_WRAP(void), Windows::Security::Cryptography::Certificates::Certificate const&);
            this->shim().ClientCertificate(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocket> : produce_base<D, Windows::Networking::Sockets::IWebSocket>
{
    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRequestHeader(void* headerName, void* headerValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRequestHeader, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().SetRequestHeader(*reinterpret_cast<hstring const*>(&headerName), *reinterpret_cast<hstring const*>(&headerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::IWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Sockets::IWebSocket, Windows::Networking::Sockets::WebSocketClosedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL CloseWithStatus(uint16_t code, void* reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void), uint16_t, hstring const&);
            this->shim().Close(code, *reinterpret_cast<hstring const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketClosedEventArgs> : produce_base<D, Windows::Networking::Sockets::IWebSocketClosedEventArgs>
{
    int32_t WINRT_CALL get_Code(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reason(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketControl> : produce_base<D, Windows::Networking::Sockets::IWebSocketControl>
{
    int32_t WINRT_CALL get_OutboundBufferSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OutboundBufferSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutboundBufferSizeInBytes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBufferSizeInBytes, WINRT_WRAP(void), uint32_t);
            this->shim().OutboundBufferSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *value = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().ServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServerCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().ServerCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProxyCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *value = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().ProxyCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProxyCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().ProxyCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedProtocols(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedProtocols, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedProtocols());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketControl2> : produce_base<D, Windows::Networking::Sockets::IWebSocketControl2>
{
    int32_t WINRT_CALL get_IgnorableServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnorableServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().IgnorableServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketErrorStatics> : produce_base<D, Windows::Networking::Sockets::IWebSocketErrorStatics>
{
    int32_t WINRT_CALL GetStatus(int32_t hresult, Windows::Web::WebErrorStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStatus, WINRT_WRAP(Windows::Web::WebErrorStatus), int32_t);
            *status = detach_from<Windows::Web::WebErrorStatus>(this->shim().GetStatus(hresult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketInformation> : produce_base<D, Windows::Networking::Sockets::IWebSocketInformation>
{
    int32_t WINRT_CALL get_LocalAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BandwidthStatistics(struct struct_Windows_Networking_Sockets_BandwidthStatistics* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthStatistics, WINRT_WRAP(Windows::Networking::Sockets::BandwidthStatistics));
            *value = detach_from<Windows::Networking::Sockets::BandwidthStatistics>(this->shim().BandwidthStatistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Protocol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Protocol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketInformation2> : produce_base<D, Windows::Networking::Sockets::IWebSocketInformation2>
{
    int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrorSeverity, WINRT_WRAP(Windows::Networking::Sockets::SocketSslErrorSeverity));
            *value = detach_from<Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerIntermediateCertificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs> : produce_base<D, Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs>
{
    int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrorSeverity, WINRT_WRAP(Windows::Networking::Sockets::SocketSslErrorSeverity));
            *value = detach_from<Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerIntermediateCertificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reject() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reject, WINRT_WRAP(void));
            this->shim().Reject();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

inline ControlChannelTrigger::ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes) :
    ControlChannelTrigger(impl::call_factory<ControlChannelTrigger, Windows::Networking::Sockets::IControlChannelTriggerFactory>([&](auto&& f) { return f.CreateControlChannelTrigger(channelId, serverKeepAliveIntervalInMinutes); }))
{}

inline ControlChannelTrigger::ControlChannelTrigger(param::hstring const& channelId, uint32_t serverKeepAliveIntervalInMinutes, Windows::Networking::Sockets::ControlChannelTriggerResourceType const& resourceRequestType) :
    ControlChannelTrigger(impl::call_factory<ControlChannelTrigger, Windows::Networking::Sockets::IControlChannelTriggerFactory>([&](auto&& f) { return f.CreateControlChannelTriggerEx(channelId, serverKeepAliveIntervalInMinutes, resourceRequestType); }))
{}

inline DatagramSocket::DatagramSocket() :
    DatagramSocket(impl::call_factory<DatagramSocket>([](auto&& f) { return f.template ActivateInstance<DatagramSocket>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> DatagramSocket::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName)
{
    return impl::call_factory<DatagramSocket, Windows::Networking::Sockets::IDatagramSocketStatics>([&](auto&& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> DatagramSocket::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions)
{
    return impl::call_factory<DatagramSocket, Windows::Networking::Sockets::IDatagramSocketStatics>([&](auto&& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName, sortOptions); });
}

inline MessageWebSocket::MessageWebSocket() :
    MessageWebSocket(impl::call_factory<MessageWebSocket>([](auto&& f) { return f.template ActivateInstance<MessageWebSocket>(); }))
{}

inline SocketActivityContext::SocketActivityContext(Windows::Storage::Streams::IBuffer const& data) :
    SocketActivityContext(impl::call_factory<SocketActivityContext, Windows::Networking::Sockets::ISocketActivityContextFactory>([&](auto&& f) { return f.Create(data); }))
{}

inline Windows::Foundation::Collections::IMapView<hstring, Windows::Networking::Sockets::SocketActivityInformation> SocketActivityInformation::AllSockets()
{
    return impl::call_factory<SocketActivityInformation, Windows::Networking::Sockets::ISocketActivityInformationStatics>([&](auto&& f) { return f.AllSockets(); });
}

inline Windows::Networking::Sockets::SocketErrorStatus SocketError::GetStatus(int32_t hresult)
{
    return impl::call_factory<SocketError, Windows::Networking::Sockets::ISocketErrorStatics>([&](auto&& f) { return f.GetStatus(hresult); });
}

inline StreamSocket::StreamSocket() :
    StreamSocket(impl::call_factory<StreamSocket>([](auto&& f) { return f.template ActivateInstance<StreamSocket>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> StreamSocket::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName)
{
    return impl::call_factory<StreamSocket, Windows::Networking::Sockets::IStreamSocketStatics>([&](auto&& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>> StreamSocket::GetEndpointPairsAsync(Windows::Networking::HostName const& remoteHostName, param::hstring const& remoteServiceName, Windows::Networking::HostNameSortOptions const& sortOptions)
{
    return impl::call_factory<StreamSocket, Windows::Networking::Sockets::IStreamSocketStatics>([&](auto&& f) { return f.GetEndpointPairsAsync(remoteHostName, remoteServiceName, sortOptions); });
}

inline StreamSocketListener::StreamSocketListener() :
    StreamSocketListener(impl::call_factory<StreamSocketListener>([](auto&& f) { return f.template ActivateInstance<StreamSocketListener>(); }))
{}

inline StreamWebSocket::StreamWebSocket() :
    StreamWebSocket(impl::call_factory<StreamWebSocket>([](auto&& f) { return f.template ActivateInstance<StreamWebSocket>(); }))
{}

inline Windows::Web::WebErrorStatus WebSocketError::GetStatus(int32_t hresult)
{
    return impl::call_factory<WebSocketError, Windows::Networking::Sockets::IWebSocketErrorStatics>([&](auto&& f) { return f.GetStatus(hresult); });
}

inline WebSocketKeepAlive::WebSocketKeepAlive() :
    WebSocketKeepAlive(impl::call_factory<WebSocketKeepAlive>([](auto&& f) { return f.template ActivateInstance<WebSocketKeepAlive>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTrigger> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IControlChannelTrigger> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTrigger2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IControlChannelTrigger2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IControlChannelTriggerEventDetails> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IControlChannelTriggerFactory> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IControlChannelTriggerResetEventDetails> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocket2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocket3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocket3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketControl3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketControl3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IDatagramSocketStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IDatagramSocketStatics> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocket2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocket3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocket3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocketControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IMessageWebSocketMessageReceivedEventArgs2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IServerMessageWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IServerMessageWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IServerMessageWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IServerStreamWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IServerStreamWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IServerStreamWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityContext> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketActivityContext> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityContextFactory> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketActivityContextFactory> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketActivityInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketActivityInformationStatics> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketActivityTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ISocketErrorStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ISocketErrorStatics> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocket2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocket3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocket3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketControl3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketControl4> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketControl4> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketInformation2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketInformation2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListener> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListener2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListener3> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListener3> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListenerConnectionReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListenerControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketListenerInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamSocketStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamSocketStatics> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocket2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamWebSocket2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IStreamWebSocketControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IStreamWebSocketControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketClosedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketControl2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketControl2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketErrorStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketErrorStatics> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketInformation2> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketInformation2> {};
template<> struct hash<winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::IWebSocketServerCustomValidationRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ControlChannelTrigger> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ControlChannelTrigger> {};
template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::DatagramSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::DatagramSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::DatagramSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::DatagramSocketMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::MessageWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::MessageWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::MessageWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::MessageWebSocketMessageReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ServerMessageWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ServerMessageWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ServerMessageWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ServerStreamWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ServerStreamWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::ServerStreamWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityContext> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::SocketActivityContext> {};
template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::SocketActivityInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::SocketActivityTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::SocketActivityTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::Sockets::SocketError> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::SocketError> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListener> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketListener> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketListenerConnectionReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketListenerControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamSocketListenerInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamSocketListenerInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocket> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamWebSocket> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocketControl> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamWebSocketControl> {};
template<> struct hash<winrt::Windows::Networking::Sockets::StreamWebSocketInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::StreamWebSocketInformation> {};
template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::WebSocketClosedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketError> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::WebSocketError> {};
template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketKeepAlive> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::WebSocketKeepAlive> {};
template<> struct hash<winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Sockets::WebSocketServerCustomValidationRequestedEventArgs> {};

}
