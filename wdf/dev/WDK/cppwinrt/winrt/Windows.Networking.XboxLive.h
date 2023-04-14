// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Networking.XboxLive.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::SnapshotChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->add_SnapshotChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::SnapshotChanged_revoker consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::SnapshotChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SnapshotChanged_revoker>(this, SnapshotChanged(handler));
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::SnapshotChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->remove_SnapshotChanged(get_abi(token)));
}

template <typename D> hstring consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::GetSnapshotAsBase64() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->GetSnapshotAsBase64(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::GetSnapshotAsBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->GetSnapshotAsBuffer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::GetSnapshotAsBytes(array_view<uint8_t> buffer, uint32_t& bytesWritten) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->GetSnapshotAsBytes(buffer.size(), get_abi(buffer), &bytesWritten));
}

template <typename D> int32_t consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::Compare(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& otherDeviceAddress) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->Compare(get_abi(otherDeviceAddress), &result));
    return result;
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::IsValid() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->get_IsValid(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::IsLocal() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->get_IsLocal(&value));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveNetworkAccessKind consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddress<D>::NetworkAccessKind() const
{
    Windows::Networking::XboxLive::XboxLiveNetworkAccessKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddress)->get_NetworkAccessKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>::CreateFromSnapshotBase64(param::hstring const& base64) const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics)->CreateFromSnapshotBase64(get_abi(base64), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>::CreateFromSnapshotBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics)->CreateFromSnapshotBuffer(get_abi(buffer), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>::CreateFromSnapshotBytes(array_view<uint8_t const> buffer) const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics)->CreateFromSnapshotBytes(buffer.size(), get_abi(buffer), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>::GetLocal() const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics)->GetLocal(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveDeviceAddressStatics<D>::MaxSnapshotBytesSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics)->get_MaxSnapshotBytesSize(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::StateChanged_revoker consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->remove_StateChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->DeleteAsync(put_abi(action)));
    return action;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::GetRemoteSocketAddressBytes(array_view<uint8_t> socketAddress) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->GetRemoteSocketAddressBytes(socketAddress.size(), get_abi(socketAddress)));
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::GetLocalSocketAddressBytes(array_view<uint8_t> socketAddress) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->GetLocalSocketAddressBytes(socketAddress.size(), get_abi(socketAddress)));
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairState consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::State() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::Template() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_Template(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::RemoteDeviceAddress() const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_RemoteDeviceAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::RemoteHostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_RemoteHostName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::RemotePort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_RemotePort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::LocalHostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_LocalHostName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_XboxLive_IXboxLiveEndpointPair<D>::LocalPort() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPair)->get_LocalPort(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult<D>::DeviceAddress() const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult)->get_DeviceAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult<D>::Status() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult<D>::IsExistingPathEvaluation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult)->get_IsExistingPathEvaluation(&value));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPair consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairCreationResult<D>::EndpointPair() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult)->get_EndpointPair(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairState consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStateChangedEventArgs<D>::OldState() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs)->get_OldState(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairState consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStateChangedEventArgs<D>::NewState() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs)->get_NewState(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPair consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStatics<D>::FindEndpointPairBySocketAddressBytes(array_view<uint8_t const> localSocketAddress, array_view<uint8_t const> remoteSocketAddress) const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair endpointPair{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics)->FindEndpointPairBySocketAddressBytes(localSocketAddress.size(), get_abi(localSocketAddress), remoteSocketAddress.size(), get_abi(remoteSocketAddress), put_abi(endpointPair)));
    return endpointPair;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPair consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairStatics<D>::FindEndpointPairByHostNamesAndPorts(Windows::Networking::HostName const& localHostName, param::hstring const& localPort, Windows::Networking::HostName const& remoteHostName, param::hstring const& remotePort) const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair endpointPair{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics)->FindEndpointPairByHostNamesAndPorts(get_abi(localHostName), get_abi(localPort), get_abi(remoteHostName), get_abi(remotePort), put_abi(endpointPair)));
    return endpointPair;
}

template <typename D> winrt::event_token consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InboundEndpointPairCreated(Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->add_InboundEndpointPairCreated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InboundEndpointPairCreated_revoker consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InboundEndpointPairCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InboundEndpointPairCreated_revoker>(this, InboundEndpointPairCreated(handler));
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InboundEndpointPairCreated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->remove_InboundEndpointPairCreated(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::CreateEndpointPairAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->CreateEndpointPairDefaultAsync(get_abi(deviceAddress), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::CreateEndpointPairAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const& behaviors) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->CreateEndpointPairWithBehaviorsAsync(get_abi(deviceAddress), get_abi(behaviors), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::CreateEndpointPairForPortsAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, param::hstring const& initiatorPort, param::hstring const& acceptorPort) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->CreateEndpointPairForPortsDefaultAsync(get_abi(deviceAddress), get_abi(initiatorPort), get_abi(acceptorPort), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::CreateEndpointPairForPortsAsync(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, param::hstring const& initiatorPort, param::hstring const& acceptorPort, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const& behaviors) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->CreateEndpointPairForPortsWithBehaviorsAsync(get_abi(deviceAddress), get_abi(initiatorPort), get_abi(acceptorPort), get_abi(behaviors), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveSocketKind consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::SocketKind() const
{
    Windows::Networking::XboxLive::XboxLiveSocketKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_SocketKind(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InitiatorBoundPortRangeLower() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_InitiatorBoundPortRangeLower(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::InitiatorBoundPortRangeUpper() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_InitiatorBoundPortRangeUpper(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::AcceptorBoundPortRangeLower() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_AcceptorBoundPortRangeLower(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::AcceptorBoundPortRangeUpper() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_AcceptorBoundPortRangeUpper(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPair> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplate<D>::EndpointPairs() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPair> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate)->get_EndpointPairs(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplateStatics<D>::GetTemplateByName(param::hstring const& name) const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate namedTemplate{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics)->GetTemplateByName(get_abi(name), put_abi(namedTemplate)));
    return namedTemplate;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> consume_Windows_Networking_XboxLive_IXboxLiveEndpointPairTemplateStatics<D>::Templates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics)->get_Templates(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveEndpointPair consume_Windows_Networking_XboxLive_IXboxLiveInboundEndpointPairCreatedEventArgs<D>::EndpointPair() const
{
    Windows::Networking::XboxLive::XboxLiveEndpointPair value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs)->get_EndpointPair(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::MeasureAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->MeasureAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::GetMetricResultsForDevice(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->GetMetricResultsForDevice(get_abi(deviceAddress), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::GetMetricResultsForMetric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const& metric) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->GetMetricResultsForMetric(get_abi(metric), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::GetMetricResult(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress, Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const& metric) const
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->GetMetricResult(get_abi(deviceAddress), get_abi(metric), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::GetPrivatePayloadResult(Windows::Networking::XboxLive::XboxLiveDeviceAddress const& deviceAddress) const
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->GetPrivatePayloadResult(get_abi(deviceAddress), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::Metrics() const
{
    Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_Metrics(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveDeviceAddress> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::DeviceAddresses() const
{
    Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveDeviceAddress> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_DeviceAddresses(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::ShouldRequestPrivatePayloads() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_ShouldRequestPrivatePayloads(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::ShouldRequestPrivatePayloads(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->put_ShouldRequestPrivatePayloads(value));
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::TimeoutInMilliseconds() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_TimeoutInMilliseconds(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::TimeoutInMilliseconds(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->put_TimeoutInMilliseconds(value));
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::NumberOfProbesToAttempt() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_NumberOfProbesToAttempt(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::NumberOfProbesToAttempt(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->put_NumberOfProbesToAttempt(value));
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::NumberOfResultsPending() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_NumberOfResultsPending(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::MetricResults() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_MetricResults(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult> consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurement<D>::PrivatePayloadResults() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement)->get_PrivatePayloadResults(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::PublishPrivatePayloadBytes(array_view<uint8_t const> payload) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->PublishPrivatePayloadBytes(payload.size(), get_abi(payload)));
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::ClearPrivatePayload() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->ClearPrivatePayload());
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::MaxSimultaneousProbeConnections() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->get_MaxSimultaneousProbeConnections(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::MaxSimultaneousProbeConnections(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->put_MaxSimultaneousProbeConnections(value));
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::IsSystemOutboundBandwidthConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->get_IsSystemOutboundBandwidthConstrained(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::IsSystemOutboundBandwidthConstrained(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->put_IsSystemOutboundBandwidthConstrained(value));
}

template <typename D> bool consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::IsSystemInboundBandwidthConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->get_IsSystemInboundBandwidthConstrained(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::IsSystemInboundBandwidthConstrained(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->put_IsSystemInboundBandwidthConstrained(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::PublishedPrivatePayload() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->get_PublishedPrivatePayload(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::PublishedPrivatePayload(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->put_PublishedPrivatePayload(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMeasurementStatics<D>::MaxPrivatePayloadSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics)->get_MaxPrivatePayloadSize(&value));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult<D>::Status() const
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult<D>::DeviceAddress() const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult)->get_DeviceAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult<D>::Metric() const
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult)->get_Metric(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServiceMetricResult<D>::Value() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult)->get_Value(&value));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServicePrivatePayloadResult<D>::Status() const
{
    Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::XboxLive::XboxLiveDeviceAddress consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServicePrivatePayloadResult<D>::DeviceAddress() const
{
    Windows::Networking::XboxLive::XboxLiveDeviceAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult)->get_DeviceAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_XboxLive_IXboxLiveQualityOfServicePrivatePayloadResult<D>::Value() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveDeviceAddress> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveDeviceAddress>
{
    int32_t WINRT_CALL add_SnapshotChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SnapshotChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SnapshotChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveDeviceAddress, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SnapshotChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SnapshotChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SnapshotChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetSnapshotAsBase64(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSnapshotAsBase64, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetSnapshotAsBase64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSnapshotAsBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSnapshotAsBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetSnapshotAsBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSnapshotAsBytes(uint32_t __bufferSize, uint8_t* buffer, uint32_t* bytesWritten) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSnapshotAsBytes, WINRT_WRAP(void), array_view<uint8_t>, uint32_t&);
            this->shim().GetSnapshotAsBytes(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize), *bytesWritten);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Compare(void* otherDeviceAddress, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compare, WINRT_WRAP(int32_t), Windows::Networking::XboxLive::XboxLiveDeviceAddress const&);
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&otherDeviceAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsValid(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsValid, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsValid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLocal(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLocal, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLocal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAccessKind(Windows::Networking::XboxLive::XboxLiveNetworkAccessKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccessKind, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveNetworkAccessKind));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveNetworkAccessKind>(this->shim().NetworkAccessKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>
{
    int32_t WINRT_CALL CreateFromSnapshotBase64(void* base64, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSnapshotBase64, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress), hstring const&);
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().CreateFromSnapshotBase64(*reinterpret_cast<hstring const*>(&base64)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromSnapshotBuffer(void* buffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSnapshotBuffer, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().CreateFromSnapshotBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromSnapshotBytes(uint32_t __bufferSize, uint8_t* buffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSnapshotBytes, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress), array_view<uint8_t const>);
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().CreateFromSnapshotBytes(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocal, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().GetLocal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSnapshotBytesSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSnapshotBytesSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxSnapshotBytesSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPair> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPair>
{
    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPair, Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL DeleteAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRemoteSocketAddressBytes(uint32_t __socketAddressSize, uint8_t* socketAddress) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRemoteSocketAddressBytes, WINRT_WRAP(void), array_view<uint8_t>);
            this->shim().GetRemoteSocketAddressBytes(array_view<uint8_t>(reinterpret_cast<uint8_t*>(socketAddress), reinterpret_cast<uint8_t*>(socketAddress) + __socketAddressSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalSocketAddressBytes(uint32_t __socketAddressSize, uint8_t* socketAddress) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalSocketAddressBytes, WINRT_WRAP(void), array_view<uint8_t>);
            this->shim().GetLocalSocketAddressBytes(array_view<uint8_t>(reinterpret_cast<uint8_t*>(socketAddress), reinterpret_cast<uint8_t*>(socketAddress) + __socketAddressSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairState));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Template(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteDeviceAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteDeviceAddress, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().RemoteDeviceAddress());
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

    int32_t WINRT_CALL get_LocalHostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalHostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().LocalHostName());
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
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult>
{
    int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAddress, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().DeviceAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsExistingPathEvaluation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExistingPathEvaluation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsExistingPathEvaluation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointPair(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointPair, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPair));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPair>(this->shim().EndpointPair());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs>
{
    int32_t WINRT_CALL get_OldState(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldState, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairState));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairState>(this->shim().OldState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewState(Windows::Networking::XboxLive::XboxLiveEndpointPairState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewState, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairState));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>
{
    int32_t WINRT_CALL FindEndpointPairBySocketAddressBytes(uint32_t __localSocketAddressSize, uint8_t* localSocketAddress, uint32_t __remoteSocketAddressSize, uint8_t* remoteSocketAddress, void** endpointPair) noexcept final
    {
        try
        {
            *endpointPair = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindEndpointPairBySocketAddressBytes, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPair), array_view<uint8_t const>, array_view<uint8_t const>);
            *endpointPair = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPair>(this->shim().FindEndpointPairBySocketAddressBytes(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(localSocketAddress), reinterpret_cast<uint8_t const *>(localSocketAddress) + __localSocketAddressSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(remoteSocketAddress), reinterpret_cast<uint8_t const *>(remoteSocketAddress) + __remoteSocketAddressSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindEndpointPairByHostNamesAndPorts(void* localHostName, void* localPort, void* remoteHostName, void* remotePort, void** endpointPair) noexcept final
    {
        try
        {
            *endpointPair = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindEndpointPairByHostNamesAndPorts, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPair), Windows::Networking::HostName const&, hstring const&, Windows::Networking::HostName const&, hstring const&);
            *endpointPair = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPair>(this->shim().FindEndpointPairByHostNamesAndPorts(*reinterpret_cast<Windows::Networking::HostName const*>(&localHostName), *reinterpret_cast<hstring const*>(&localPort), *reinterpret_cast<Windows::Networking::HostName const*>(&remoteHostName), *reinterpret_cast<hstring const*>(&remotePort)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate>
{
    int32_t WINRT_CALL add_InboundEndpointPairCreated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundEndpointPairCreated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InboundEndpointPairCreated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InboundEndpointPairCreated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InboundEndpointPairCreated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InboundEndpointPairCreated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateEndpointPairDefaultAsync(void* deviceAddress, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEndpointPairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>), Windows::Networking::XboxLive::XboxLiveDeviceAddress const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>>(this->shim().CreateEndpointPairAsync(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEndpointPairWithBehaviorsAsync(void* deviceAddress, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors behaviors, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEndpointPairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>), Windows::Networking::XboxLive::XboxLiveDeviceAddress const, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>>(this->shim().CreateEndpointPairAsync(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress), *reinterpret_cast<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const*>(&behaviors)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEndpointPairForPortsDefaultAsync(void* deviceAddress, void* initiatorPort, void* acceptorPort, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEndpointPairForPortsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>), Windows::Networking::XboxLive::XboxLiveDeviceAddress const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>>(this->shim().CreateEndpointPairForPortsAsync(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress), *reinterpret_cast<hstring const*>(&initiatorPort), *reinterpret_cast<hstring const*>(&acceptorPort)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEndpointPairForPortsWithBehaviorsAsync(void* deviceAddress, void* initiatorPort, void* acceptorPort, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors behaviors, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEndpointPairForPortsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>), Windows::Networking::XboxLive::XboxLiveDeviceAddress const, hstring const, hstring const, Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult>>(this->shim().CreateEndpointPairForPortsAsync(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress), *reinterpret_cast<hstring const*>(&initiatorPort), *reinterpret_cast<hstring const*>(&acceptorPort), *reinterpret_cast<Windows::Networking::XboxLive::XboxLiveEndpointPairCreationBehaviors const*>(&behaviors)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SocketKind(Windows::Networking::XboxLive::XboxLiveSocketKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SocketKind, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveSocketKind));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveSocketKind>(this->shim().SocketKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitiatorBoundPortRangeLower(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitiatorBoundPortRangeLower, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().InitiatorBoundPortRangeLower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitiatorBoundPortRangeUpper(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitiatorBoundPortRangeUpper, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().InitiatorBoundPortRangeUpper());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcceptorBoundPortRangeLower(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptorBoundPortRangeLower, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AcceptorBoundPortRangeLower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcceptorBoundPortRangeUpper(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptorBoundPortRangeUpper, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AcceptorBoundPortRangeUpper());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointPairs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointPairs, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPair>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPair>>(this->shim().EndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>
{
    int32_t WINRT_CALL GetTemplateByName(void* name, void** namedTemplate) noexcept final
    {
        try
        {
            *namedTemplate = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTemplateByName, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate), hstring const&);
            *namedTemplate = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>(this->shim().GetTemplateByName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Templates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Templates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate>>(this->shim().Templates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs>
{
    int32_t WINRT_CALL get_EndpointPair(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointPair, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveEndpointPair));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveEndpointPair>(this->shim().EndpointPair());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement>
{
    int32_t WINRT_CALL MeasureAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeasureAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MeasureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMetricResultsForDevice(void* deviceAddress, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMetricResultsForDevice, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>), Windows::Networking::XboxLive::XboxLiveDeviceAddress const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>>(this->shim().GetMetricResultsForDevice(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMetricResultsForMetric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric metric, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMetricResultsForMetric, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>), Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>>(this->shim().GetMetricResultsForMetric(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const*>(&metric)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMetricResult(void* deviceAddress, Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric metric, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMetricResult, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult), Windows::Networking::XboxLive::XboxLiveDeviceAddress const&, Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const&);
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>(this->shim().GetMetricResult(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress), *reinterpret_cast<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric const*>(&metric)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPrivatePayloadResult(void* deviceAddress, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPrivatePayloadResult, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult), Windows::Networking::XboxLive::XboxLiveDeviceAddress const&);
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>(this->shim().GetPrivatePayloadResult(*reinterpret_cast<Windows::Networking::XboxLive::XboxLiveDeviceAddress const*>(&deviceAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Metrics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Metrics, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric>>(this->shim().Metrics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceAddresses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAddresses, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveDeviceAddress>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Networking::XboxLive::XboxLiveDeviceAddress>>(this->shim().DeviceAddresses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldRequestPrivatePayloads(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldRequestPrivatePayloads, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldRequestPrivatePayloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldRequestPrivatePayloads(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldRequestPrivatePayloads, WINRT_WRAP(void), bool);
            this->shim().ShouldRequestPrivatePayloads(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeoutInMilliseconds(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeoutInMilliseconds, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TimeoutInMilliseconds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TimeoutInMilliseconds(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeoutInMilliseconds, WINRT_WRAP(void), uint32_t);
            this->shim().TimeoutInMilliseconds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfProbesToAttempt(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfProbesToAttempt, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NumberOfProbesToAttempt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NumberOfProbesToAttempt(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfProbesToAttempt, WINRT_WRAP(void), uint32_t);
            this->shim().NumberOfProbesToAttempt(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfResultsPending(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfResultsPending, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NumberOfResultsPending());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MetricResults(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetricResults, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult>>(this->shim().MetricResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrivatePayloadResults(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivatePayloadResults, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult>>(this->shim().PrivatePayloadResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>
{
    int32_t WINRT_CALL PublishPrivatePayloadBytes(uint32_t __payloadSize, uint8_t* payload) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishPrivatePayloadBytes, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().PublishPrivatePayloadBytes(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(payload), reinterpret_cast<uint8_t const *>(payload) + __payloadSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearPrivatePayload() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearPrivatePayload, WINRT_WRAP(void));
            this->shim().ClearPrivatePayload();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSimultaneousProbeConnections(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSimultaneousProbeConnections, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxSimultaneousProbeConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxSimultaneousProbeConnections(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSimultaneousProbeConnections, WINRT_WRAP(void), uint32_t);
            this->shim().MaxSimultaneousProbeConnections(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSystemOutboundBandwidthConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemOutboundBandwidthConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSystemOutboundBandwidthConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSystemOutboundBandwidthConstrained(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemOutboundBandwidthConstrained, WINRT_WRAP(void), bool);
            this->shim().IsSystemOutboundBandwidthConstrained(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSystemInboundBandwidthConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemInboundBandwidthConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSystemInboundBandwidthConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSystemInboundBandwidthConstrained(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemInboundBandwidthConstrained, WINRT_WRAP(void), bool);
            this->shim().IsSystemInboundBandwidthConstrained(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublishedPrivatePayload(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishedPrivatePayload, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PublishedPrivatePayload());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PublishedPrivatePayload(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishedPrivatePayload, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().PublishedPrivatePayload(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPrivatePayloadSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPrivatePayloadSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPrivatePayloadSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAddress, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().DeviceAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Metric(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Metric, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetric>(this->shim().Metric());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult> : produce_base<D, Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurementStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAddress, WINRT_WRAP(Windows::Networking::XboxLive::XboxLiveDeviceAddress));
            *value = detach_from<Windows::Networking::XboxLive::XboxLiveDeviceAddress>(this->shim().DeviceAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::XboxLive {

inline Windows::Networking::XboxLive::XboxLiveDeviceAddress XboxLiveDeviceAddress::CreateFromSnapshotBase64(param::hstring const& base64)
{
    return impl::call_factory<XboxLiveDeviceAddress, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>([&](auto&& f) { return f.CreateFromSnapshotBase64(base64); });
}

inline Windows::Networking::XboxLive::XboxLiveDeviceAddress XboxLiveDeviceAddress::CreateFromSnapshotBuffer(Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<XboxLiveDeviceAddress, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>([&](auto&& f) { return f.CreateFromSnapshotBuffer(buffer); });
}

inline Windows::Networking::XboxLive::XboxLiveDeviceAddress XboxLiveDeviceAddress::CreateFromSnapshotBytes(array_view<uint8_t const> buffer)
{
    return impl::call_factory<XboxLiveDeviceAddress, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>([&](auto&& f) { return f.CreateFromSnapshotBytes(buffer); });
}

inline Windows::Networking::XboxLive::XboxLiveDeviceAddress XboxLiveDeviceAddress::GetLocal()
{
    return impl::call_factory<XboxLiveDeviceAddress, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>([&](auto&& f) { return f.GetLocal(); });
}

inline uint32_t XboxLiveDeviceAddress::MaxSnapshotBytesSize()
{
    return impl::call_factory<XboxLiveDeviceAddress, Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics>([&](auto&& f) { return f.MaxSnapshotBytesSize(); });
}

inline Windows::Networking::XboxLive::XboxLiveEndpointPair XboxLiveEndpointPair::FindEndpointPairBySocketAddressBytes(array_view<uint8_t const> localSocketAddress, array_view<uint8_t const> remoteSocketAddress)
{
    return impl::call_factory<XboxLiveEndpointPair, Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>([&](auto&& f) { return f.FindEndpointPairBySocketAddressBytes(localSocketAddress, remoteSocketAddress); });
}

inline Windows::Networking::XboxLive::XboxLiveEndpointPair XboxLiveEndpointPair::FindEndpointPairByHostNamesAndPorts(Windows::Networking::HostName const& localHostName, param::hstring const& localPort, Windows::Networking::HostName const& remoteHostName, param::hstring const& remotePort)
{
    return impl::call_factory<XboxLiveEndpointPair, Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics>([&](auto&& f) { return f.FindEndpointPairByHostNamesAndPorts(localHostName, localPort, remoteHostName, remotePort); });
}

inline Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate XboxLiveEndpointPairTemplate::GetTemplateByName(param::hstring const& name)
{
    return impl::call_factory<XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>([&](auto&& f) { return f.GetTemplateByName(name); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> XboxLiveEndpointPairTemplate::Templates()
{
    return impl::call_factory<XboxLiveEndpointPairTemplate, Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics>([&](auto&& f) { return f.Templates(); });
}

inline XboxLiveQualityOfServiceMeasurement::XboxLiveQualityOfServiceMeasurement() :
    XboxLiveQualityOfServiceMeasurement(impl::call_factory<XboxLiveQualityOfServiceMeasurement>([](auto&& f) { return f.template ActivateInstance<XboxLiveQualityOfServiceMeasurement>(); }))
{}

inline void XboxLiveQualityOfServiceMeasurement::PublishPrivatePayloadBytes(array_view<uint8_t const> payload)
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.PublishPrivatePayloadBytes(payload); });
}

inline void XboxLiveQualityOfServiceMeasurement::ClearPrivatePayload()
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.ClearPrivatePayload(); });
}

inline uint32_t XboxLiveQualityOfServiceMeasurement::MaxSimultaneousProbeConnections()
{
    return impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.MaxSimultaneousProbeConnections(); });
}

inline void XboxLiveQualityOfServiceMeasurement::MaxSimultaneousProbeConnections(uint32_t value)
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.MaxSimultaneousProbeConnections(value); });
}

inline bool XboxLiveQualityOfServiceMeasurement::IsSystemOutboundBandwidthConstrained()
{
    return impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.IsSystemOutboundBandwidthConstrained(); });
}

inline void XboxLiveQualityOfServiceMeasurement::IsSystemOutboundBandwidthConstrained(bool value)
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.IsSystemOutboundBandwidthConstrained(value); });
}

inline bool XboxLiveQualityOfServiceMeasurement::IsSystemInboundBandwidthConstrained()
{
    return impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.IsSystemInboundBandwidthConstrained(); });
}

inline void XboxLiveQualityOfServiceMeasurement::IsSystemInboundBandwidthConstrained(bool value)
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.IsSystemInboundBandwidthConstrained(value); });
}

inline Windows::Storage::Streams::IBuffer XboxLiveQualityOfServiceMeasurement::PublishedPrivatePayload()
{
    return impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.PublishedPrivatePayload(); });
}

inline void XboxLiveQualityOfServiceMeasurement::PublishedPrivatePayload(Windows::Storage::Streams::IBuffer const& value)
{
    impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.PublishedPrivatePayload(value); });
}

inline uint32_t XboxLiveQualityOfServiceMeasurement::MaxPrivatePayloadSize()
{
    return impl::call_factory<XboxLiveQualityOfServiceMeasurement, Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics>([&](auto&& f) { return f.MaxPrivatePayloadSize(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveDeviceAddress> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveDeviceAddress> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveDeviceAddressStatics> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPair> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPair> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairCreationResult> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairStatics> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplate> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveEndpointPairTemplateStatics> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveInboundEndpointPairCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurement> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMeasurementStatics> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServiceMetricResult> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::IXboxLiveQualityOfServicePrivatePayloadResult> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveDeviceAddress> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveDeviceAddress> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPair> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPair> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairCreationResult> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveEndpointPairTemplate> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveInboundEndpointPairCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurement> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServiceMeasurement> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServiceMetricResult> {};
template<> struct hash<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult> : winrt::impl::hash_base<winrt::Windows::Networking::XboxLive::XboxLiveQualityOfServicePrivatePayloadResult> {};

}
