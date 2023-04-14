// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Networking.Proximity.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> Windows::Networking::Proximity::PeerInformation consume_Windows_Networking_Proximity_IConnectionRequestedEventArgs<D>::PeerInformation() const
{
    Windows::Networking::Proximity::PeerInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IConnectionRequestedEventArgs)->get_PeerInformation(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowBluetooth() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowBluetooth(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowBluetooth(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowBluetooth(value));
}

template <typename D> bool consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowInfrastructure() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowInfrastructure(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowInfrastructure(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowInfrastructure(value));
}

template <typename D> bool consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowWiFiDirect() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_AllowWiFiDirect(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AllowWiFiDirect(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->put_AllowWiFiDirect(value));
}

template <typename D> hstring consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->put_DisplayName(get_abi(value)));
}

template <typename D> Windows::Networking::Proximity::PeerDiscoveryTypes consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::SupportedDiscoveryTypes() const
{
    Windows::Networking::Proximity::PeerDiscoveryTypes value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_SupportedDiscoveryTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::AlternateIdentities() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->get_AlternateIdentities(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->Start());
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Start(param::hstring const& peerMessage) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->StartWithMessage(get_abi(peerMessage)));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->add_TriggeredConnectionStateChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged_revoker consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TriggeredConnectionStateChanged_revoker>(this, TriggeredConnectionStateChanged(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::TriggeredConnectionStateChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->remove_TriggeredConnectionStateChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->add_ConnectionRequested(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested_revoker consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ConnectionRequested_revoker>(this, ConnectionRequested(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectionRequested(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->remove_ConnectionRequested(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>> consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::FindAllPeersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->FindAllPeersAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket> consume_Windows_Networking_Proximity_IPeerFinderStatics<D>::ConnectAsync(Windows::Networking::Proximity::PeerInformation const& peerInformation) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics)->ConnectAsync(get_abi(peerInformation), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Networking::Proximity::PeerRole consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::Role() const
{
    Windows::Networking::Proximity::PeerRole value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics2)->get_Role(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::Role(Windows::Networking::Proximity::PeerRole const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics2)->put_Role(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::DiscoveryData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics2)->get_DiscoveryData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::DiscoveryData(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics2)->put_DiscoveryData(get_abi(value)));
}

template <typename D> Windows::Networking::Proximity::PeerWatcher consume_Windows_Networking_Proximity_IPeerFinderStatics2<D>::CreateWatcher() const
{
    Windows::Networking::Proximity::PeerWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerFinderStatics2)->CreateWatcher(put_abi(watcher)));
    return watcher;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IPeerInformation<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerInformation)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IPeerInformation3<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerInformation3)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Proximity_IPeerInformation3<D>::DiscoveryData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerInformation3)->get_DiscoveryData(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>::HostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerInformationWithHostAndService)->get_HostName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IPeerInformationWithHostAndService<D>::ServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerInformationWithHostAndService)->get_ServiceName(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped_revoker consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Networking::Proximity::PeerWatcherStatus consume_Windows_Networking_Proximity_IPeerWatcher<D>::Status() const
{
    Windows::Networking::Proximity::PeerWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->Start());
}

template <typename D> void consume_Windows_Networking_Proximity_IPeerWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IPeerWatcher)->Stop());
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::SubscribeForMessage(param::hstring const& messageType, Windows::Networking::Proximity::MessageReceivedHandler const& messageReceivedHandler) const
{
    int64_t subscriptionId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->SubscribeForMessage(get_abi(messageType), get_abi(messageReceivedHandler), &subscriptionId));
    return subscriptionId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishMessage(param::hstring const& messageType, param::hstring const& message) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishMessage(get_abi(messageType), get_abi(message), &messageId));
    return messageId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishMessage(param::hstring const& messageType, param::hstring const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishMessageWithCallback(get_abi(messageType), get_abi(message), get_abi(messageTransmittedHandler), &messageId));
    return messageId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishBinaryMessage(param::hstring const& messageType, Windows::Storage::Streams::IBuffer const& message) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishBinaryMessage(get_abi(messageType), get_abi(message), &messageId));
    return messageId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishBinaryMessage(param::hstring const& messageType, Windows::Storage::Streams::IBuffer const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishBinaryMessageWithCallback(get_abi(messageType), get_abi(message), get_abi(messageTransmittedHandler), &messageId));
    return messageId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishUriMessage(Windows::Foundation::Uri const& message) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishUriMessage(get_abi(message), &messageId));
    return messageId;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::PublishUriMessage(Windows::Foundation::Uri const& message, Windows::Networking::Proximity::MessageTransmittedHandler const& messageTransmittedHandler) const
{
    int64_t messageId{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->PublishUriMessageWithCallback(get_abi(message), get_abi(messageTransmittedHandler), &messageId));
    return messageId;
}

template <typename D> void consume_Windows_Networking_Proximity_IProximityDevice<D>::StopSubscribingForMessage(int64_t subscriptionId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->StopSubscribingForMessage(subscriptionId));
}

template <typename D> void consume_Windows_Networking_Proximity_IProximityDevice<D>::StopPublishingMessage(int64_t messageId) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->StopPublishingMessage(messageId));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->add_DeviceArrived(get_abi(arrivedHandler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived_revoker consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(auto_revoke_t, Windows::Networking::Proximity::DeviceArrivedEventHandler const& arrivedHandler) const
{
    return impl::make_event_revoker<D, DeviceArrived_revoker>(this, DeviceArrived(arrivedHandler));
}

template <typename D> void consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceArrived(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->remove_DeviceArrived(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->add_DeviceDeparted(get_abi(departedHandler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted_revoker consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(auto_revoke_t, Windows::Networking::Proximity::DeviceDepartedEventHandler const& departedHandler) const
{
    return impl::make_event_revoker<D, DeviceDeparted_revoker>(this, DeviceDeparted(departedHandler));
}

template <typename D> void consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceDeparted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->remove_DeviceDeparted(get_abi(cookie)));
}

template <typename D> uint32_t consume_Windows_Networking_Proximity_IProximityDevice<D>::MaxMessageBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->get_MaxMessageBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Proximity_IProximityDevice<D>::BitsPerSecond() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->get_BitsPerSecond(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IProximityDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::GetDeviceSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDeviceStatics)->GetDeviceSelector(put_abi(selector)));
    return selector;
}

template <typename D> Windows::Networking::Proximity::ProximityDevice consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::GetDefault() const
{
    Windows::Networking::Proximity::ProximityDevice proximityDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDeviceStatics)->GetDefault(put_abi(proximityDevice)));
    return proximityDevice;
}

template <typename D> Windows::Networking::Proximity::ProximityDevice consume_Windows_Networking_Proximity_IProximityDeviceStatics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Networking::Proximity::ProximityDevice proximityDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityDeviceStatics)->FromId(get_abi(deviceId), put_abi(proximityDevice)));
    return proximityDevice;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IProximityMessage<D>::MessageType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityMessage)->get_MessageType(put_abi(value)));
    return value;
}

template <typename D> int64_t consume_Windows_Networking_Proximity_IProximityMessage<D>::SubscriptionId() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityMessage)->get_SubscriptionId(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Proximity_IProximityMessage<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityMessage)->get_Data(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Proximity_IProximityMessage<D>::DataAsString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::IProximityMessage)->get_DataAsString(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Proximity::TriggeredConnectState consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::State() const
{
    Windows::Networking::Proximity::TriggeredConnectState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_Id(&value));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocket consume_Windows_Networking_Proximity_ITriggeredConnectionStateChangedEventArgs<D>::Socket() const
{
    Windows::Networking::Sockets::StreamSocket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs)->get_Socket(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::Networking::Proximity::DeviceArrivedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Networking::Proximity::DeviceArrivedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Networking::Proximity::DeviceArrivedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Networking::Proximity::ProximityDevice const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Networking::Proximity::DeviceDepartedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Networking::Proximity::DeviceDepartedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Networking::Proximity::DeviceDepartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Networking::Proximity::ProximityDevice const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Networking::Proximity::MessageReceivedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Networking::Proximity::MessageReceivedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Networking::Proximity::MessageReceivedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* message) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Networking::Proximity::ProximityDevice const*>(&sender), *reinterpret_cast<Windows::Networking::Proximity::ProximityMessage const*>(&message));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Networking::Proximity::MessageTransmittedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Networking::Proximity::MessageTransmittedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Networking::Proximity::MessageTransmittedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, int64_t messageId) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Networking::Proximity::ProximityDevice const*>(&sender), messageId);
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IConnectionRequestedEventArgs> : produce_base<D, Windows::Networking::Proximity::IConnectionRequestedEventArgs>
{
    int32_t WINRT_CALL get_PeerInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerInformation, WINRT_WRAP(Windows::Networking::Proximity::PeerInformation));
            *value = detach_from<Windows::Networking::Proximity::PeerInformation>(this->shim().PeerInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerFinderStatics> : produce_base<D, Windows::Networking::Proximity::IPeerFinderStatics>
{
    int32_t WINRT_CALL get_AllowBluetooth(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowBluetooth, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowBluetooth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowBluetooth(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowBluetooth, WINRT_WRAP(void), bool);
            this->shim().AllowBluetooth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowInfrastructure(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowInfrastructure, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowInfrastructure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowInfrastructure(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowInfrastructure, WINRT_WRAP(void), bool);
            this->shim().AllowInfrastructure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowWiFiDirect(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowWiFiDirect, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowWiFiDirect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowWiFiDirect(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowWiFiDirect, WINRT_WRAP(void), bool);
            this->shim().AllowWiFiDirect(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedDiscoveryTypes(Windows::Networking::Proximity::PeerDiscoveryTypes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDiscoveryTypes, WINRT_WRAP(Windows::Networking::Proximity::PeerDiscoveryTypes));
            *value = detach_from<Windows::Networking::Proximity::PeerDiscoveryTypes>(this->shim().SupportedDiscoveryTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateIdentities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateIdentities, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AlternateIdentities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartWithMessage(void* peerMessage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void), hstring const&);
            this->shim().Start(*reinterpret_cast<hstring const*>(&peerMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TriggeredConnectionStateChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggeredConnectionStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().TriggeredConnectionStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TriggeredConnectionStateChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TriggeredConnectionStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TriggeredConnectionStateChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ConnectionRequested(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ConnectionRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionRequested(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL FindAllPeersAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllPeersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>>>(this->shim().FindAllPeersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void* peerInformation, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket>), Windows::Networking::Proximity::PeerInformation const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Networking::Proximity::PeerInformation const*>(&peerInformation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerFinderStatics2> : produce_base<D, Windows::Networking::Proximity::IPeerFinderStatics2>
{
    int32_t WINRT_CALL get_Role(Windows::Networking::Proximity::PeerRole* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Role, WINRT_WRAP(Windows::Networking::Proximity::PeerRole));
            *value = detach_from<Windows::Networking::Proximity::PeerRole>(this->shim().Role());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Role(Windows::Networking::Proximity::PeerRole value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Role, WINRT_WRAP(void), Windows::Networking::Proximity::PeerRole const&);
            this->shim().Role(*reinterpret_cast<Windows::Networking::Proximity::PeerRole const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DiscoveryData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscoveryData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DiscoveryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DiscoveryData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscoveryData, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().DiscoveryData(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcher(void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Networking::Proximity::PeerWatcher));
            *watcher = detach_from<Windows::Networking::Proximity::PeerWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerInformation> : produce_base<D, Windows::Networking::Proximity::IPeerInformation>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerInformation3> : produce_base<D, Windows::Networking::Proximity::IPeerInformation3>
{
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

    int32_t WINRT_CALL get_DiscoveryData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscoveryData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DiscoveryData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerInformationWithHostAndService> : produce_base<D, Windows::Networking::Proximity::IPeerInformationWithHostAndService>
{
    int32_t WINRT_CALL get_HostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().HostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IPeerWatcher> : produce_base<D, Windows::Networking::Proximity::IPeerWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Networking::Proximity::PeerInformation> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::Proximity::PeerWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Networking::Proximity::PeerWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::Proximity::PeerWatcherStatus));
            *status = detach_from<Windows::Networking::Proximity::PeerWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IProximityDevice> : produce_base<D, Windows::Networking::Proximity::IProximityDevice>
{
    int32_t WINRT_CALL SubscribeForMessage(void* messageType, void* messageReceivedHandler, int64_t* subscriptionId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscribeForMessage, WINRT_WRAP(int64_t), hstring const&, Windows::Networking::Proximity::MessageReceivedHandler const&);
            *subscriptionId = detach_from<int64_t>(this->shim().SubscribeForMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<Windows::Networking::Proximity::MessageReceivedHandler const*>(&messageReceivedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishMessage(void* messageType, void* message, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishMessage, WINRT_WRAP(int64_t), hstring const&, hstring const&);
            *messageId = detach_from<int64_t>(this->shim().PublishMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishMessage, WINRT_WRAP(int64_t), hstring const&, hstring const&, Windows::Networking::Proximity::MessageTransmittedHandler const&);
            *messageId = detach_from<int64_t>(this->shim().PublishMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<hstring const*>(&message), *reinterpret_cast<Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishBinaryMessage(void* messageType, void* message, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishBinaryMessage, WINRT_WRAP(int64_t), hstring const&, Windows::Storage::Streams::IBuffer const&);
            *messageId = detach_from<int64_t>(this->shim().PublishBinaryMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishBinaryMessageWithCallback(void* messageType, void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishBinaryMessage, WINRT_WRAP(int64_t), hstring const&, Windows::Storage::Streams::IBuffer const&, Windows::Networking::Proximity::MessageTransmittedHandler const&);
            *messageId = detach_from<int64_t>(this->shim().PublishBinaryMessage(*reinterpret_cast<hstring const*>(&messageType), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&message), *reinterpret_cast<Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishUriMessage(void* message, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishUriMessage, WINRT_WRAP(int64_t), Windows::Foundation::Uri const&);
            *messageId = detach_from<int64_t>(this->shim().PublishUriMessage(*reinterpret_cast<Windows::Foundation::Uri const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishUriMessageWithCallback(void* message, void* messageTransmittedHandler, int64_t* messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishUriMessage, WINRT_WRAP(int64_t), Windows::Foundation::Uri const&, Windows::Networking::Proximity::MessageTransmittedHandler const&);
            *messageId = detach_from<int64_t>(this->shim().PublishUriMessage(*reinterpret_cast<Windows::Foundation::Uri const*>(&message), *reinterpret_cast<Windows::Networking::Proximity::MessageTransmittedHandler const*>(&messageTransmittedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopSubscribingForMessage(int64_t subscriptionId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopSubscribingForMessage, WINRT_WRAP(void), int64_t);
            this->shim().StopSubscribingForMessage(subscriptionId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopPublishingMessage(int64_t messageId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPublishingMessage, WINRT_WRAP(void), int64_t);
            this->shim().StopPublishingMessage(messageId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DeviceArrived(void* arrivedHandler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceArrived, WINRT_WRAP(winrt::event_token), Windows::Networking::Proximity::DeviceArrivedEventHandler const&);
            *cookie = detach_from<winrt::event_token>(this->shim().DeviceArrived(*reinterpret_cast<Windows::Networking::Proximity::DeviceArrivedEventHandler const*>(&arrivedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeviceArrived(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeviceArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeviceArrived(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_DeviceDeparted(void* departedHandler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceDeparted, WINRT_WRAP(winrt::event_token), Windows::Networking::Proximity::DeviceDepartedEventHandler const&);
            *cookie = detach_from<winrt::event_token>(this->shim().DeviceDeparted(*reinterpret_cast<Windows::Networking::Proximity::DeviceDepartedEventHandler const*>(&departedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeviceDeparted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeviceDeparted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeviceDeparted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_MaxMessageBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessageBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxMessageBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitsPerSecond(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitsPerSecond, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IProximityDeviceStatics> : produce_base<D, Windows::Networking::Proximity::IProximityDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** proximityDevice) noexcept final
    {
        try
        {
            *proximityDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Networking::Proximity::ProximityDevice));
            *proximityDevice = detach_from<Windows::Networking::Proximity::ProximityDevice>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromId(void* deviceId, void** proximityDevice) noexcept final
    {
        try
        {
            *proximityDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Networking::Proximity::ProximityDevice), hstring const&);
            *proximityDevice = detach_from<Windows::Networking::Proximity::ProximityDevice>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::IProximityMessage> : produce_base<D, Windows::Networking::Proximity::IProximityMessage>
{
    int32_t WINRT_CALL get_MessageType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MessageType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubscriptionId(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscriptionId, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().SubscriptionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_DataAsString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataAsString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DataAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> : produce_base<D, Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Networking::Proximity::TriggeredConnectState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Networking::Proximity::TriggeredConnectState));
            *value = detach_from<Windows::Networking::Proximity::TriggeredConnectState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

}

WINRT_EXPORT namespace winrt::Windows::Networking::Proximity {

inline bool PeerFinder::AllowBluetooth()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowBluetooth(); });
}

inline void PeerFinder::AllowBluetooth(bool value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowBluetooth(value); });
}

inline bool PeerFinder::AllowInfrastructure()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowInfrastructure(); });
}

inline void PeerFinder::AllowInfrastructure(bool value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowInfrastructure(value); });
}

inline bool PeerFinder::AllowWiFiDirect()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowWiFiDirect(); });
}

inline void PeerFinder::AllowWiFiDirect(bool value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AllowWiFiDirect(value); });
}

inline hstring PeerFinder::DisplayName()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.DisplayName(); });
}

inline void PeerFinder::DisplayName(param::hstring const& value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.DisplayName(value); });
}

inline Windows::Networking::Proximity::PeerDiscoveryTypes PeerFinder::SupportedDiscoveryTypes()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.SupportedDiscoveryTypes(); });
}

inline Windows::Foundation::Collections::IMap<hstring, hstring> PeerFinder::AlternateIdentities()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.AlternateIdentities(); });
}

inline void PeerFinder::Start()
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.Start(); });
}

inline void PeerFinder::Start(param::hstring const& peerMessage)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.Start(peerMessage); });
}

inline void PeerFinder::Stop()
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.Stop(); });
}

inline winrt::event_token PeerFinder::TriggeredConnectionStateChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler)
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.TriggeredConnectionStateChanged(handler); });
}

inline PeerFinder::TriggeredConnectionStateChanged_revoker PeerFinder::TriggeredConnectionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>();
    return { f, f.TriggeredConnectionStateChanged(handler) };
}

inline void PeerFinder::TriggeredConnectionStateChanged(winrt::event_token const& cookie)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.TriggeredConnectionStateChanged(cookie); });
}

inline winrt::event_token PeerFinder::ConnectionRequested(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler)
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.ConnectionRequested(handler); });
}

inline PeerFinder::ConnectionRequested_revoker PeerFinder::ConnectionRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Networking::Proximity::ConnectionRequestedEventArgs> const& handler)
{
    auto f = get_activation_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>();
    return { f, f.ConnectionRequested(handler) };
}

inline void PeerFinder::ConnectionRequested(winrt::event_token const& cookie)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.ConnectionRequested(cookie); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Proximity::PeerInformation>> PeerFinder::FindAllPeersAsync()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.FindAllPeersAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::Sockets::StreamSocket> PeerFinder::ConnectAsync(Windows::Networking::Proximity::PeerInformation const& peerInformation)
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics>([&](auto&& f) { return f.ConnectAsync(peerInformation); });
}

inline Windows::Networking::Proximity::PeerRole PeerFinder::Role()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics2>([&](auto&& f) { return f.Role(); });
}

inline void PeerFinder::Role(Windows::Networking::Proximity::PeerRole const& value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics2>([&](auto&& f) { return f.Role(value); });
}

inline Windows::Storage::Streams::IBuffer PeerFinder::DiscoveryData()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics2>([&](auto&& f) { return f.DiscoveryData(); });
}

inline void PeerFinder::DiscoveryData(Windows::Storage::Streams::IBuffer const& value)
{
    impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics2>([&](auto&& f) { return f.DiscoveryData(value); });
}

inline Windows::Networking::Proximity::PeerWatcher PeerFinder::CreateWatcher()
{
    return impl::call_factory<PeerFinder, Windows::Networking::Proximity::IPeerFinderStatics2>([&](auto&& f) { return f.CreateWatcher(); });
}

inline hstring ProximityDevice::GetDeviceSelector()
{
    return impl::call_factory<ProximityDevice, Windows::Networking::Proximity::IProximityDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Networking::Proximity::ProximityDevice ProximityDevice::GetDefault()
{
    return impl::call_factory<ProximityDevice, Windows::Networking::Proximity::IProximityDeviceStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Networking::Proximity::ProximityDevice ProximityDevice::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<ProximityDevice, Windows::Networking::Proximity::IProximityDeviceStatics>([&](auto&& f) { return f.FromId(deviceId); });
}

template <typename L> DeviceArrivedEventHandler::DeviceArrivedEventHandler(L handler) :
    DeviceArrivedEventHandler(impl::make_delegate<DeviceArrivedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DeviceArrivedEventHandler::DeviceArrivedEventHandler(F* handler) :
    DeviceArrivedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(O* object, M method) :
    DeviceArrivedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(com_ptr<O>&& object, M method) :
    DeviceArrivedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DeviceArrivedEventHandler::DeviceArrivedEventHandler(weak_ref<O>&& object, M method) :
    DeviceArrivedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DeviceArrivedEventHandler::operator()(Windows::Networking::Proximity::ProximityDevice const& sender) const
{
    check_hresult((*(impl::abi_t<DeviceArrivedEventHandler>**)this)->Invoke(get_abi(sender)));
}

template <typename L> DeviceDepartedEventHandler::DeviceDepartedEventHandler(L handler) :
    DeviceDepartedEventHandler(impl::make_delegate<DeviceDepartedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DeviceDepartedEventHandler::DeviceDepartedEventHandler(F* handler) :
    DeviceDepartedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(O* object, M method) :
    DeviceDepartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(com_ptr<O>&& object, M method) :
    DeviceDepartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DeviceDepartedEventHandler::DeviceDepartedEventHandler(weak_ref<O>&& object, M method) :
    DeviceDepartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DeviceDepartedEventHandler::operator()(Windows::Networking::Proximity::ProximityDevice const& sender) const
{
    check_hresult((*(impl::abi_t<DeviceDepartedEventHandler>**)this)->Invoke(get_abi(sender)));
}

template <typename L> MessageReceivedHandler::MessageReceivedHandler(L handler) :
    MessageReceivedHandler(impl::make_delegate<MessageReceivedHandler>(std::forward<L>(handler)))
{}

template <typename F> MessageReceivedHandler::MessageReceivedHandler(F* handler) :
    MessageReceivedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(O* object, M method) :
    MessageReceivedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(com_ptr<O>&& object, M method) :
    MessageReceivedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> MessageReceivedHandler::MessageReceivedHandler(weak_ref<O>&& object, M method) :
    MessageReceivedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void MessageReceivedHandler::operator()(Windows::Networking::Proximity::ProximityDevice const& sender, Windows::Networking::Proximity::ProximityMessage const& message) const
{
    check_hresult((*(impl::abi_t<MessageReceivedHandler>**)this)->Invoke(get_abi(sender), get_abi(message)));
}

template <typename L> MessageTransmittedHandler::MessageTransmittedHandler(L handler) :
    MessageTransmittedHandler(impl::make_delegate<MessageTransmittedHandler>(std::forward<L>(handler)))
{}

template <typename F> MessageTransmittedHandler::MessageTransmittedHandler(F* handler) :
    MessageTransmittedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(O* object, M method) :
    MessageTransmittedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(com_ptr<O>&& object, M method) :
    MessageTransmittedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> MessageTransmittedHandler::MessageTransmittedHandler(weak_ref<O>&& object, M method) :
    MessageTransmittedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void MessageTransmittedHandler::operator()(Windows::Networking::Proximity::ProximityDevice const& sender, int64_t messageId) const
{
    check_hresult((*(impl::abi_t<MessageTransmittedHandler>**)this)->Invoke(get_abi(sender), messageId));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IConnectionRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerFinderStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerFinderStatics> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerFinderStatics2> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerFinderStatics2> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerInformation> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformation3> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerInformation3> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerInformationWithHostAndService> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IPeerWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IPeerWatcher> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IProximityDevice> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IProximityDevice> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IProximityDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IProximityDeviceStatics> {};
template<> struct hash<winrt::Windows::Networking::Proximity::IProximityMessage> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::IProximityMessage> {};
template<> struct hash<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::ITriggeredConnectionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::ConnectionRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::Proximity::PeerFinder> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::PeerFinder> {};
template<> struct hash<winrt::Windows::Networking::Proximity::PeerInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::PeerInformation> {};
template<> struct hash<winrt::Windows::Networking::Proximity::PeerWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::PeerWatcher> {};
template<> struct hash<winrt::Windows::Networking::Proximity::ProximityDevice> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::ProximityDevice> {};
template<> struct hash<winrt::Windows::Networking::Proximity::ProximityMessage> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::ProximityMessage> {};
template<> struct hash<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::Proximity::TriggeredConnectionStateChangedEventArgs> {};

}
