// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.WiFiDirect.Services.2.h"
#include "winrt/Windows.Devices.WiFiDirect.h"

namespace winrt::impl {

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::RemoteServiceInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_RemoteServiceInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SupportedConfigurationMethods() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_SupportedConfigurationMethods(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::PreferGroupOwnerMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_PreferGroupOwnerMode(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::PreferGroupOwnerMode(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->put_PreferGroupOwnerMode(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionInfo(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->put_SessionInfo(get_abi(value)));
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ServiceError() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->get_ServiceError(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectService, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->add_SessionDeferred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectService, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionDeferred_revoker>(this, SessionDeferred(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::SessionDeferred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->remove_SessionDeferred(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::GetProvisioningInfoAsync(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const& selectedConfigurationMethod) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->GetProvisioningInfoAsync(get_abi(selectedConfigurationMethod), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ConnectAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->ConnectAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectService<D>::ConnectAsync(param::hstring const& pin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectService)->ConnectAsyncWithPin(get_abi(pin), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceNamePrefixes() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceNamePrefixes(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceInfo(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_ServiceInfo(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSession() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_AutoAcceptSession(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSession(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_AutoAcceptSession(value));
}

template <typename D> bool consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferGroupOwnerMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_PreferGroupOwnerMode(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferGroupOwnerMode(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_PreferGroupOwnerMode(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::PreferredConfigurationMethods() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_PreferredConfigurationMethods(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceStatus() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceStatus(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceStatus(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_ServiceStatus(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::CustomServiceStatusCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_CustomServiceStatusCode(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::CustomServiceStatusCode(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_CustomServiceStatusCode(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::DeferredSessionInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_DeferredSessionInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::DeferredSessionInfo(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->put_DeferredSessionInfo(get_abi(value)));
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatus() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_AdvertisementStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ServiceError() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->get_ServiceError(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_SessionRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionRequested_revoker>(this, SessionRequested(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::SessionRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_SessionRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_AutoAcceptSessionConnected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AutoAcceptSessionConnected_revoker>(this, AutoAcceptSessionConnected(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AutoAcceptSessionConnected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_AutoAcceptSessionConnected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->add_AdvertisementStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AdvertisementStatusChanged_revoker>(this, AdvertisementStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::AdvertisementStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->remove_AdvertisementStatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ConnectAsync(Windows::Devices::Enumeration::DeviceInformation const& deviceInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->ConnectAsync(get_abi(deviceInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::ConnectAsync(Windows::Devices::Enumeration::DeviceInformation const& deviceInfo, param::hstring const& pin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->ConnectAsyncWithPin(get_abi(deviceInfo), get_abi(pin), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->Start());
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiser<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser)->Stop());
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAdvertiserFactory<D>::CreateWiFiDirectServiceAdvertiser(param::hstring const& serviceName) const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory)->CreateWiFiDirectServiceAdvertiser(get_abi(serviceName), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs<D>::Session() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs<D>::SessionInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo<D>::SelectedConfigurationMethod() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo)->get_SelectedConfigurationMethod(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceProvisioningInfo<D>::IsGroupFormationNeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo)->get_IsGroupFormationNeeded(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs<D>::EndpointPairs() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs)->get_EndpointPairs(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceRemotePortAddedEventArgs<D>::Protocol() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs)->get_Protocol(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ServiceName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::Status() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ErrorStatus() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ErrorStatus(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_SessionId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AdvertisementId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_AdvertisementId(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::ServiceAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_ServiceAddress(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->get_SessionAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::GetConnectionEndpointPairs() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->GetConnectionEndpointPairs(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->add_SessionStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SessionStatusChanged_revoker>(this, SessionStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::SessionStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->remove_SessionStatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AddStreamSocketListenerAsync(Windows::Networking::Sockets::StreamSocketListener const& value) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->AddStreamSocketListenerAsync(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::AddDatagramSocketAsync(Windows::Networking::Sockets::DatagramSocket const& value) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->AddDatagramSocketAsync(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->add_RemotePortAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded_revoker consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RemotePortAdded_revoker>(this, RemotePortAdded(handler));
}

template <typename D> void consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSession<D>::RemotePortAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession)->remove_RemotePortAdded(get_abi(token)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionDeferredEventArgs<D>::DeferredSessionInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs)->get_DeferredSessionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::ProvisioningInfo() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_ProvisioningInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequest<D>::SessionInfo() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceSessionRequestedEventArgs<D>::GetSessionRequest() const
{
    Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs)->GetSessionRequest(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::GetSelector(param::hstring const& serviceName) const
{
    hstring serviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->GetSelector(get_abi(serviceName), put_abi(serviceSelector)));
    return serviceSelector;
}

template <typename D> hstring consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::GetSelector(param::hstring const& serviceName, Windows::Storage::Streams::IBuffer const& serviceInfoFilter) const
{
    hstring serviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->GetSelectorWithFilter(get_abi(serviceName), get_abi(serviceInfoFilter), put_abi(serviceSelector)));
    return serviceSelector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectService> consume_Windows_Devices_WiFiDirect_Services_IWiFiDirectServiceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectService> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics)->FromIdAsync(get_abi(deviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectService> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectService>
{
    int32_t WINRT_CALL get_RemoteServiceInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteServiceInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().RemoteServiceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedConfigurationMethods(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedConfigurationMethods, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>>(this->shim().SupportedConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferGroupOwnerMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferGroupOwnerMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PreferGroupOwnerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferGroupOwnerMode(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferGroupOwnerMode, WINRT_WRAP(void), bool);
            this->shim().PreferGroupOwnerMode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SessionInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().SessionInfo(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceError(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceError, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError>(this->shim().ServiceError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SessionDeferred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionDeferred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectService, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionDeferred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectService, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionDeferred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionDeferred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionDeferred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetProvisioningInfoAsync(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod selectedConfigurationMethod, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProvisioningInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>), Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>>(this->shim().GetProvisioningInfoAsync(*reinterpret_cast<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod const*>(&selectedConfigurationMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsyncWithPin(void* pin, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<hstring const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser>
{
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

    int32_t WINRT_CALL get_ServiceNamePrefixes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceNamePrefixes, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ServiceNamePrefixes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ServiceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServiceInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceInfo, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().ServiceInfo(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoAcceptSession(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoAcceptSession, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoAcceptSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoAcceptSession(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoAcceptSession, WINRT_WRAP(void), bool);
            this->shim().AutoAcceptSession(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferGroupOwnerMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferGroupOwnerMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PreferGroupOwnerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferGroupOwnerMode(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferGroupOwnerMode, WINRT_WRAP(void), bool);
            this->shim().PreferGroupOwnerMode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredConfigurationMethods(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredConfigurationMethods, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>>(this->shim().PreferredConfigurationMethods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceStatus(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceStatus, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus>(this->shim().ServiceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServiceStatus(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceStatus, WINRT_WRAP(void), Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const&);
            this->shim().ServiceStatus(*reinterpret_cast<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomServiceStatusCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomServiceStatusCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomServiceStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomServiceStatusCode(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomServiceStatusCode, WINRT_WRAP(void), uint32_t);
            this->shim().CustomServiceStatusCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeferredSessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferredSessionInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeferredSessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeferredSessionInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferredSessionInfo, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().DeferredSessionInfo(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisementStatus(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementStatus, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertisementStatus>(this->shim().AdvertisementStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceError(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceError, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceError>(this->shim().ServiceError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SessionRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AutoAcceptSessionConnected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoAcceptSessionConnected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AutoAcceptSessionConnected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AutoAcceptSessionConnected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AutoAcceptSessionConnected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AutoAcceptSessionConnected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AdvertisementStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AdvertisementStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AdvertisementStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AdvertisementStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AdvertisementStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL ConnectAsync(void* deviceInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>), Windows::Devices::Enumeration::DeviceInformation const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&deviceInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsyncWithPin(void* deviceInfo, void* pin, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>), Windows::Devices::Enumeration::DeviceInformation const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&deviceInfo), *reinterpret_cast<hstring const*>(&pin)));
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
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>
{
    int32_t WINRT_CALL CreateWiFiDirectServiceAdvertiser(void* serviceName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWiFiDirectServiceAdvertiser, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser), hstring const&);
            *result = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser>(this->shim().CreateWiFiDirectServiceAdvertiser(*reinterpret_cast<hstring const*>(&serviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo>
{
    int32_t WINRT_CALL get_SelectedConfigurationMethod(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedConfigurationMethod, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceConfigurationMethod>(this->shim().SelectedConfigurationMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGroupFormationNeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGroupFormationNeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGroupFormationNeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs>
{
    int32_t WINRT_CALL get_EndpointPairs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointPairs, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>(this->shim().EndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Protocol(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Protocol, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceIPProtocol>(this->shim().Protocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession>
{
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

    int32_t WINRT_CALL get_Status(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorStatus(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorStatus, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionErrorStatus>(this->shim().ErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisementId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AdvertisementId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SessionAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConnectionEndpointPairs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectionEndpointPairs, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>(this->shim().GetConnectionEndpointPairs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SessionStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL AddStreamSocketListenerAsync(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddStreamSocketListenerAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::Sockets::StreamSocketListener const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AddStreamSocketListenerAsync(*reinterpret_cast<Windows::Networking::Sockets::StreamSocketListener const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddDatagramSocketAsync(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddDatagramSocketAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::Sockets::DatagramSocket const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AddDatagramSocketAsync(*reinterpret_cast<Windows::Networking::Sockets::DatagramSocket const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RemotePortAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemotePortAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemotePortAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession, Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemotePortAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemotePortAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemotePortAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs>
{
    int32_t WINRT_CALL get_DeferredSessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferredSessionInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().DeferredSessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest>
{
    int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProvisioningInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisioningInfo, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo>(this->shim().ProvisioningInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs>
{
    int32_t WINRT_CALL GetSessionRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSessionRequest, WINRT_WRAP(Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest));
            *value = detach_from<Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest>(this->shim().GetSessionRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> : produce_base<D, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>
{
    int32_t WINRT_CALL GetSelector(void* serviceName, void** serviceSelector) noexcept final
    {
        try
        {
            *serviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelector, WINRT_WRAP(hstring), hstring const&);
            *serviceSelector = detach_from<hstring>(this->shim().GetSelector(*reinterpret_cast<hstring const*>(&serviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSelectorWithFilter(void* serviceName, void* serviceInfoFilter, void** serviceSelector) noexcept final
    {
        try
        {
            *serviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelector, WINRT_WRAP(hstring), hstring const&, Windows::Storage::Streams::IBuffer const&);
            *serviceSelector = detach_from<hstring>(this->shim().GetSelector(*reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&serviceInfoFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectService>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectService>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::WiFiDirect::Services {

inline hstring WiFiDirectService::GetSelector(param::hstring const& serviceName)
{
    return impl::call_factory<WiFiDirectService, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>([&](auto&& f) { return f.GetSelector(serviceName); });
}

inline hstring WiFiDirectService::GetSelector(param::hstring const& serviceName, Windows::Storage::Streams::IBuffer const& serviceInfoFilter)
{
    return impl::call_factory<WiFiDirectService, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>([&](auto&& f) { return f.GetSelector(serviceName, serviceInfoFilter); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::WiFiDirect::Services::WiFiDirectService> WiFiDirectService::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<WiFiDirectService, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline WiFiDirectServiceAdvertiser::WiFiDirectServiceAdvertiser(param::hstring const& serviceName) :
    WiFiDirectServiceAdvertiser(impl::call_factory<WiFiDirectServiceAdvertiser, Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory>([&](auto&& f) { return f.CreateWiFiDirectServiceAdvertiser(serviceName); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectService> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiser> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAdvertiserFactory> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceAutoAcceptSessionConnectedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceProvisioningInfo> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceRemotePortAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSession> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionDeferredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequest> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceSessionRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::IWiFiDirectServiceStatics> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectService> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAdvertiser> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceAutoAcceptSessionConnectedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceProvisioningInfo> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceRemotePortAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSession> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionDeferredEventArgs> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequest> {};
template<> struct hash<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::WiFiDirect::Services::WiFiDirectServiceSessionRequestedEventArgs> {};

}
