// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::AppService() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_AppService(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::LaunchUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_LaunchUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::RemoteSession() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_RemoteSession(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IKnownRemoteSystemCapabilitiesStatics<D>::SpatialEntity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics)->get_SpatialEntity(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystem<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Kind() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemStatus consume_Windows_System_RemoteSystems_IRemoteSystem<D>::Status() const
{
    Windows::System::RemoteSystems::RemoteSystemStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystem<D>::IsAvailableByProximity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem)->get_IsAvailableByProximity(&value));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystem2<D>::IsAvailableBySpatialProximity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem2)->get_IsAvailableBySpatialProximity(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystem2<D>::GetCapabilitySupportedAsync(param::hstring const& capabilityName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem2)->GetCapabilitySupportedAsync(get_abi(capabilityName), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystem3<D>::ManufacturerDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem3)->get_ManufacturerDisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystem3<D>::ModelDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem3)->get_ModelDisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemPlatform consume_Windows_System_RemoteSystems_IRemoteSystem4<D>::Platform() const
{
    Windows::System::RemoteSystems::RemoteSystemPlatform value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem4)->get_Platform(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::RemoteSystems::RemoteSystemApp> consume_Windows_System_RemoteSystems_IRemoteSystem5<D>::Apps() const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::RemoteSystems::RemoteSystemApp> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem5)->get_Apps(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_RemoteSystems_IRemoteSystem6<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystem6)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystem consume_Windows_System_RemoteSystems_IRemoteSystemAddedEventArgs<D>::RemoteSystem() const
{
    Windows::System::RemoteSystems::RemoteSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs)->get_RemoteSystem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::IsAvailableByProximity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp)->get_IsAvailableByProximity(&value));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::IsAvailableBySpatialProximity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp)->get_IsAvailableBySpatialProximity(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_System_RemoteSystems_IRemoteSystemApp<D>::Attributes() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp)->get_Attributes(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_RemoteSystems_IRemoteSystemApp2<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp2)->get_User(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemApp2<D>::ConnectionToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemApp2)->get_ConnectionToken(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::Attributes() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->get_Attributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistration<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAppRegistration)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemAppRegistration consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistrationStatics<D>::GetDefault() const
{
    Windows::System::RemoteSystems::RemoteSystemAppRegistration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemAppRegistration consume_Windows_System_RemoteSystems_IRemoteSystemAppRegistrationStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::RemoteSystems::RemoteSystemAppRegistration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemAuthorizationKind consume_Windows_System_RemoteSystems_IRemoteSystemAuthorizationKindFilter<D>::RemoteSystemAuthorizationKind() const
{
    Windows::System::RemoteSystems::RemoteSystemAuthorizationKind value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter)->get_RemoteSystemAuthorizationKind(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter consume_Windows_System_RemoteSystems_IRemoteSystemAuthorizationKindFilterFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& remoteSystemAuthorizationKind) const
{
    Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory)->Create(get_abi(remoteSystemAuthorizationKind), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystemConnectionInfo<D>::IsProximal() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionInfo)->get_IsProximal(&value));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemConnectionInfo consume_Windows_System_RemoteSystems_IRemoteSystemConnectionInfoStatics<D>::TryCreateFromAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& connection) const
{
    Windows::System::RemoteSystems::RemoteSystemConnectionInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics)->TryCreateFromAppServiceConnection(get_abi(connection), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystem consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest<D>::RemoteSystem() const
{
    Windows::System::RemoteSystems::RemoteSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequest)->get_RemoteSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemApp consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest2<D>::RemoteSystemApp() const
{
    Windows::System::RemoteSystems::RemoteSystemApp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2)->get_RemoteSystemApp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequest3<D>::ConnectionToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3)->get_ConnectionToken(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemConnectionRequest consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystem const& remoteSystem) const
{
    Windows::System::RemoteSystems::RemoteSystemConnectionRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory)->Create(get_abi(remoteSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemConnectionRequest consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics<D>::CreateForApp(Windows::System::RemoteSystems::RemoteSystemApp const& remoteSystemApp) const
{
    Windows::System::RemoteSystems::RemoteSystemConnectionRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics)->CreateForApp(get_abi(remoteSystemApp), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemConnectionRequest consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics2<D>::CreateFromConnectionToken(param::hstring const& connectionToken) const
{
    Windows::System::RemoteSystems::RemoteSystemConnectionRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2)->CreateFromConnectionToken(get_abi(connectionToken), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemConnectionRequest consume_Windows_System_RemoteSystems_IRemoteSystemConnectionRequestStatics2<D>::CreateFromConnectionTokenForUser(Windows::System::User const& user, param::hstring const& connectionToken) const
{
    Windows::System::RemoteSystems::RemoteSystemConnectionRequest result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2)->CreateFromConnectionTokenForUser(get_abi(user), get_abi(connectionToken), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemDiscoveryType consume_Windows_System_RemoteSystems_IRemoteSystemDiscoveryTypeFilter<D>::RemoteSystemDiscoveryType() const
{
    Windows::System::RemoteSystems::RemoteSystemDiscoveryType value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter)->get_RemoteSystemDiscoveryType(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter consume_Windows_System_RemoteSystems_IRemoteSystemDiscoveryTypeFilterFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystemDiscoveryType const& discoveryType) const
{
    Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory)->Create(get_abi(discoveryType), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_RemoteSystems_IRemoteSystemKindFilter<D>::RemoteSystemKinds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindFilter)->get_RemoteSystemKinds(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemKindFilter consume_Windows_System_RemoteSystems_IRemoteSystemKindFilterFactory<D>::Create(param::iterable<hstring> const& remoteSystemKinds) const
{
    Windows::System::RemoteSystems::RemoteSystemKindFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory)->Create(get_abi(remoteSystemKinds), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Phone() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Phone(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Hub() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Hub(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Holographic() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Holographic(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Desktop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Desktop(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics<D>::Xbox() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics)->get_Xbox(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Iot() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Iot(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Tablet() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Tablet(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemKindStatics2<D>::Laptop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemKindStatics2)->get_Laptop(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemRemovedEventArgs<D>::RemoteSystemId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs)->get_RemoteSystemId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::ControllerDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->get_ControllerDisplayName(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSession, Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->add_Disconnected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSession, Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Disconnected_revoker>(this, Disconnected(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::Disconnected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->remove_Disconnected(get_abi(token)));
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::CreateParticipantWatcher() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->CreateParticipantWatcher(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemSession<D>::SendInvitationAsync(Windows::System::RemoteSystems::RemoteSystem const& invitee) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSession)->SendInvitationAsync(get_abi(invitee), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionInfo consume_Windows_System_RemoteSystems_IRemoteSystemSessionAddedEventArgs<D>::SessionInfo() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionController, Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionController)->add_JoinRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionController, Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, JoinRequested_revoker>(this, JoinRequested(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::JoinRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionController)->remove_JoinRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::RemoveParticipantAsync(Windows::System::RemoteSystems::RemoteSystemSessionParticipant const& pParticipant) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionController)->RemoveParticipantAsync(get_abi(pParticipant), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionCreationResult> consume_Windows_System_RemoteSystems_IRemoteSystemSessionController<D>::CreateSessionAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionCreationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionController)->CreateSessionAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionController consume_Windows_System_RemoteSystems_IRemoteSystemSessionControllerFactory<D>::CreateController(param::hstring const& displayName) const
{
    Windows::System::RemoteSystems::RemoteSystemSessionController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory)->CreateController(get_abi(displayName), put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionController consume_Windows_System_RemoteSystems_IRemoteSystemSessionControllerFactory<D>::CreateController(param::hstring const& displayName, Windows::System::RemoteSystems::RemoteSystemSessionOptions const& options) const
{
    Windows::System::RemoteSystems::RemoteSystemSessionController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory)->CreateControllerWithSessionOptions(get_abi(displayName), get_abi(options), put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus consume_Windows_System_RemoteSystems_IRemoteSystemSessionCreationResult<D>::Status() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSession consume_Windows_System_RemoteSystems_IRemoteSystemSessionCreationResult<D>::Session() const
{
    Windows::System::RemoteSystems::RemoteSystemSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason consume_Windows_System_RemoteSystems_IRemoteSystemSessionDisconnectedEventArgs<D>::Reason() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::ControllerDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->get_ControllerDisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionJoinResult> consume_Windows_System_RemoteSystems_IRemoteSystemSessionInfo<D>::JoinAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionJoinResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInfo)->JoinAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystem consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitation<D>::Sender() const
{
    Windows::System::RemoteSystems::RemoteSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInvitation)->get_Sender(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionInfo consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitation<D>::SessionInfo() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInvitation)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener)->add_InvitationReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InvitationReceived_revoker>(this, InvitationReceived(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationListener<D>::InvitationReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener)->remove_InvitationReceived(get_abi(token)));
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionInvitation consume_Windows_System_RemoteSystems_IRemoteSystemSessionInvitationReceivedEventArgs<D>::Invitation() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionInvitation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs)->get_Invitation(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipant consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequest<D>::Participant() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipant value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest)->get_Participant(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequest<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest)->Accept());
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequestedEventArgs<D>::JoinRequest() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs)->get_JoinRequest(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinResult<D>::Status() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSession consume_Windows_System_RemoteSystems_IRemoteSystemSessionJoinResult<D>::Session() const
{
    Windows::System::RemoteSystems::RemoteSystemSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSession consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::Session() const
{
    Windows::System::RemoteSystems::RemoteSystemSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::BroadcastValueSetAsync(Windows::Foundation::Collections::ValueSet const& messageData) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->BroadcastValueSetAsync(get_abi(messageData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::SendValueSetAsync(Windows::Foundation::Collections::ValueSet const& messageData, Windows::System::RemoteSystems::RemoteSystemSessionParticipant const& participant) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->SendValueSetAsync(get_abi(messageData), get_abi(participant), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::SendValueSetToParticipantsAsync(Windows::Foundation::Collections::ValueSet const& messageData, param::async_iterable<Windows::System::RemoteSystems::RemoteSystemSessionParticipant> const& participants) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->SendValueSetToParticipantsAsync(get_abi(messageData), get_abi(participants), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->add_ValueSetReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ValueSetReceived_revoker>(this, ValueSetReceived(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannel<D>::ValueSetReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel)->remove_ValueSetReceived(get_abi(token)));
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannelFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName) const
{
    Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory)->Create(get_abi(session), get_abi(channelName), put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel consume_Windows_System_RemoteSystems_IRemoteSystemSessionMessageChannelFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName, Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const& reliability) const
{
    Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory)->CreateWithReliability(get_abi(session), get_abi(channelName), get_abi(reliability), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystemSessionOptions<D>::IsInviteOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionOptions)->get_IsInviteOnly(&value));
    return value;
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionOptions<D>::IsInviteOnly(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionOptions)->put_IsInviteOnly(value));
}

template <typename D> Windows::System::RemoteSystems::RemoteSystem consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipant<D>::RemoteSystem() const
{
    Windows::System::RemoteSystems::RemoteSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipant)->get_RemoteSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipant<D>::GetHostNames() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipant)->GetHostNames(put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipant consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantAddedEventArgs<D>::Participant() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipant value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs)->get_Participant(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipant consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantRemovedEventArgs<D>::Participant() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipant value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs)->get_Participant(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->Start());
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->Stop());
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Status() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionParticipantWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionInfo consume_Windows_System_RemoteSystems_IRemoteSystemSessionRemovedEventArgs<D>::SessionInfo() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionWatcher consume_Windows_System_RemoteSystems_IRemoteSystemSessionStatics<D>::CreateWatcher() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionStatics)->CreateWatcher(put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionInfo consume_Windows_System_RemoteSystems_IRemoteSystemSessionUpdatedEventArgs<D>::SessionInfo() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs)->get_SessionInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionParticipant consume_Windows_System_RemoteSystems_IRemoteSystemSessionValueSetReceivedEventArgs<D>::Sender() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionParticipant value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs)->get_Sender(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_System_RemoteSystems_IRemoteSystemSessionValueSetReceivedEventArgs<D>::Message() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->Start());
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->Stop());
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Status() const
{
    Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed_revoker consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemSessionWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemSessionWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem> consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::FindByHostNameAsync(Windows::Networking::HostName const& hostName) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics)->FindByHostNameAsync(get_abi(hostName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWatcher consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::CreateWatcher() const
{
    Windows::System::RemoteSystems::RemoteSystemWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics)->CreateWatcher(put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWatcher consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::CreateWatcher(param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters) const
{
    Windows::System::RemoteSystems::RemoteSystemWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics)->CreateWatcherWithFilters(get_abi(filters), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus> consume_Windows_System_RemoteSystems_IRemoteSystemStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_System_RemoteSystems_IRemoteSystemStatics2<D>::IsAuthorizationKindEnabled(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& kind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics2)->IsAuthorizationKindEnabled(get_abi(kind), &result));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWatcher consume_Windows_System_RemoteSystems_IRemoteSystemStatics3<D>::CreateWatcherForUser(Windows::System::User const& user) const
{
    Windows::System::RemoteSystems::RemoteSystemWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics3)->CreateWatcherForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWatcher consume_Windows_System_RemoteSystems_IRemoteSystemStatics3<D>::CreateWatcherForUser(Windows::System::User const& user, param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters) const
{
    Windows::System::RemoteSystems::RemoteSystemWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatics3)->CreateWatcherWithFiltersForUser(get_abi(user), get_abi(filters), put_abi(result)));
    return result;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemStatusType consume_Windows_System_RemoteSystems_IRemoteSystemStatusTypeFilter<D>::RemoteSystemStatusType() const
{
    Windows::System::RemoteSystems::RemoteSystemStatusType value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter)->get_RemoteSystemStatusType(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter consume_Windows_System_RemoteSystems_IRemoteSystemStatusTypeFilterFactory<D>::Create(Windows::System::RemoteSystems::RemoteSystemStatusType const& remoteSystemStatusType) const
{
    Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory)->Create(get_abi(remoteSystemStatusType), put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystem consume_Windows_System_RemoteSystems_IRemoteSystemUpdatedEventArgs<D>::RemoteSystem() const
{
    Windows::System::RemoteSystems::RemoteSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs)->get_RemoteSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->Start());
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RemoteSystemAdded_revoker>(this, RemoteSystemAdded(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RemoteSystemUpdated_revoker>(this, RemoteSystemUpdated(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->add_RemoteSystemRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RemoteSystemRemoved_revoker>(this, RemoteSystemRemoved(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher<D>::RemoteSystemRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher)->remove_RemoteSystemRemoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher2)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher2)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher2)->add_ErrorOccurred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred_revoker consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
}

template <typename D> void consume_Windows_System_RemoteSystems_IRemoteSystemWatcher2<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher2)->remove_ErrorOccurred(get_abi(token)));
}

template <typename D> Windows::System::User consume_Windows_System_RemoteSystems_IRemoteSystemWatcher3<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcher3)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWatcherError consume_Windows_System_RemoteSystems_IRemoteSystemWatcherErrorOccurredEventArgs<D>::Error() const
{
    Windows::System::RemoteSystems::RemoteSystemWatcherError value{};
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_System_RemoteSystems_IRemoteSystemWebAccountFilter<D>::Account() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter)->get_Account(put_abi(value)));
    return value;
}

template <typename D> Windows::System::RemoteSystems::RemoteSystemWebAccountFilter consume_Windows_System_RemoteSystems_IRemoteSystemWebAccountFilterFactory<D>::Create(Windows::Security::Credentials::WebAccount const& account) const
{
    Windows::System::RemoteSystems::RemoteSystemWebAccountFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory)->Create(get_abi(account), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics> : produce_base<D, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>
{
    int32_t WINRT_CALL get_AppService(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppService, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LaunchUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LaunchUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSession, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpatialEntity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatialEntity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SpatialEntity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem>
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

    int32_t WINRT_CALL get_Kind(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::System::RemoteSystems::RemoteSystemStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemStatus));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAvailableByProximity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableByProximity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailableByProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem2>
{
    int32_t WINRT_CALL get_IsAvailableBySpatialProximity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableBySpatialProximity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailableBySpatialProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCapabilitySupportedAsync(void* capabilityName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapabilitySupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetCapabilitySupportedAsync(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem3> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem3>
{
    int32_t WINRT_CALL get_ManufacturerDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ManufacturerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem4> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem4>
{
    int32_t WINRT_CALL get_Platform(Windows::System::RemoteSystems::RemoteSystemPlatform* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Platform, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemPlatform));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemPlatform>(this->shim().Platform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem5> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem5>
{
    int32_t WINRT_CALL get_Apps(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Apps, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::RemoteSystems::RemoteSystemApp>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::RemoteSystems::RemoteSystemApp>>(this->shim().Apps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystem6> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystem6>
{
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
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs>
{
    int32_t WINRT_CALL get_RemoteSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystem, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystem));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemApp> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemApp>
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

    int32_t WINRT_CALL get_IsAvailableByProximity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableByProximity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailableByProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAvailableBySpatialProximity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableBySpatialProximity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailableBySpatialProximity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Attributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attributes, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemApp2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemApp2>
{
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

    int32_t WINRT_CALL get_ConnectionToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemAppRegistration> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemAppRegistration>
{
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

    int32_t WINRT_CALL get_Attributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attributes, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemAppRegistration));
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemAppRegistration>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemAppRegistration), Windows::System::User const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemAppRegistration>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter>
{
    int32_t WINRT_CALL get_RemoteSystemAuthorizationKind(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemAuthorizationKind, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemAuthorizationKind>(this->shim().RemoteSystemAuthorizationKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory>
{
    int32_t WINRT_CALL Create(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind remoteSystemAuthorizationKind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter), Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const*>(&remoteSystemAuthorizationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionInfo> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionInfo>
{
    int32_t WINRT_CALL get_IsProximal(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProximal, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProximal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics>
{
    int32_t WINRT_CALL TryCreateFromAppServiceConnection(void* connection, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFromAppServiceConnection, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemConnectionInfo), Windows::ApplicationModel::AppService::AppServiceConnection const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemConnectionInfo>(this->shim().TryCreateFromAppServiceConnection(*reinterpret_cast<Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest>
{
    int32_t WINRT_CALL get_RemoteSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystem, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystem));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2>
{
    int32_t WINRT_CALL get_RemoteSystemApp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemApp, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemApp));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemApp>(this->shim().RemoteSystemApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3>
{
    int32_t WINRT_CALL get_ConnectionToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory>
{
    int32_t WINRT_CALL Create(void* remoteSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemConnectionRequest), Windows::System::RemoteSystems::RemoteSystem const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystem const*>(&remoteSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics>
{
    int32_t WINRT_CALL CreateForApp(void* remoteSystemApp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForApp, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemConnectionRequest), Windows::System::RemoteSystems::RemoteSystemApp const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateForApp(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemApp const*>(&remoteSystemApp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2>
{
    int32_t WINRT_CALL CreateFromConnectionToken(void* connectionToken, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromConnectionToken, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemConnectionRequest), hstring const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateFromConnectionToken(*reinterpret_cast<hstring const*>(&connectionToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromConnectionTokenForUser(void* user, void* connectionToken, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromConnectionTokenForUser, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemConnectionRequest), Windows::System::User const&, hstring const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemConnectionRequest>(this->shim().CreateFromConnectionTokenForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&connectionToken)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter>
{
    int32_t WINRT_CALL get_RemoteSystemDiscoveryType(Windows::System::RemoteSystems::RemoteSystemDiscoveryType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemDiscoveryType, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemDiscoveryType));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemDiscoveryType>(this->shim().RemoteSystemDiscoveryType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory>
{
    int32_t WINRT_CALL Create(Windows::System::RemoteSystems::RemoteSystemDiscoveryType discoveryType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter), Windows::System::RemoteSystems::RemoteSystemDiscoveryType const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemDiscoveryType const*>(&discoveryType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs>
{};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemFilter>
{};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemKindFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemKindFilter>
{
    int32_t WINRT_CALL get_RemoteSystemKinds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemKinds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().RemoteSystemKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory>
{
    int32_t WINRT_CALL Create(void* remoteSystemKinds, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemKindFilter), Windows::Foundation::Collections::IIterable<hstring> const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemKindFilter>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&remoteSystemKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemKindStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemKindStatics>
{
    int32_t WINRT_CALL get_Phone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Phone, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Phone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hub(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hub, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hub());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Holographic(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Holographic, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Holographic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Desktop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Desktop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Xbox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Xbox, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Xbox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemKindStatics2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemKindStatics2>
{
    int32_t WINRT_CALL get_Iot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Iot, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Iot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tablet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tablet, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tablet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Laptop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Laptop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Laptop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs>
{
    int32_t WINRT_CALL get_RemoteSystemId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSession> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSession>
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

    int32_t WINRT_CALL get_ControllerDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControllerDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ControllerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Disconnected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSession, Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Disconnected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSession, Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Disconnected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Disconnected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Disconnected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateParticipantWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateParticipantWatcher, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher));
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher>(this->shim().CreateParticipantWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendInvitationAsync(void* invitee, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendInvitationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::RemoteSystems::RemoteSystem const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendInvitationAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystem const*>(&invitee)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs>
{
    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionInfo));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionController> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionController>
{
    int32_t WINRT_CALL add_JoinRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JoinRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionController, Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().JoinRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionController, Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_JoinRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(JoinRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().JoinRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL RemoveParticipantAsync(void* pParticipant, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveParticipantAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::RemoteSystems::RemoteSystemSessionParticipant const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RemoveParticipantAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSessionParticipant const*>(&pParticipant)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSessionAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSessionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionCreationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionCreationResult>>(this->shim().CreateSessionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory>
{
    int32_t WINRT_CALL CreateController(void* displayName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateController, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionController), hstring const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionController>(this->shim().CreateController(*reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateControllerWithSessionOptions(void* displayName, void* options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateController, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionController), hstring const&, Windows::System::RemoteSystems::RemoteSystemSessionOptions const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionController>(this->shim().CreateController(*reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSessionOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult>
{
    int32_t WINRT_CALL get_Status(Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSession));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionInfo> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionInfo>
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

    int32_t WINRT_CALL get_ControllerDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControllerDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ControllerDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL JoinAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JoinAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionJoinResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemSessionJoinResult>>(this->shim().JoinAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitation> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitation>
{
    int32_t WINRT_CALL get_Sender(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sender, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystem));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystem>(this->shim().Sender());
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
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionInfo));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener>
{
    int32_t WINRT_CALL add_InvitationReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvitationReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InvitationReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener, Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InvitationReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InvitationReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InvitationReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs>
{
    int32_t WINRT_CALL get_Invitation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invitation, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionInvitation));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionInvitation>(this->shim().Invitation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest>
{
    int32_t WINRT_CALL get_Participant(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Participant, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipant));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Accept() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accept, WINRT_WRAP(void));
            this->shim().Accept();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs>
{
    int32_t WINRT_CALL get_JoinRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JoinRequest, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest>(this->shim().JoinRequest());
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

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult>
{
    int32_t WINRT_CALL get_Status(Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionJoinStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSession));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSession));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BroadcastValueSetAsync(void* messageData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastValueSetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().BroadcastValueSetAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&messageData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendValueSetAsync(void* messageData, void* participant, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendValueSetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::ValueSet const, Windows::System::RemoteSystems::RemoteSystemSessionParticipant const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendValueSetAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&messageData), *reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSessionParticipant const*>(&participant)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendValueSetToParticipantsAsync(void* messageData, void* participants, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendValueSetToParticipantsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::ValueSet const, Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::RemoteSystemSessionParticipant> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SendValueSetToParticipantsAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&messageData), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::RemoteSystemSessionParticipant> const*>(&participants)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ValueSetReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueSetReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ValueSetReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ValueSetReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ValueSetReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ValueSetReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory>
{
    int32_t WINRT_CALL Create(void* session, void* channelName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel), Windows::System::RemoteSystems::RemoteSystemSession const&, hstring const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSession const*>(&session), *reinterpret_cast<hstring const*>(&channelName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithReliability(void* session, void* channelName, Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability reliability, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel), Windows::System::RemoteSystems::RemoteSystemSession const&, hstring const&, Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSession const*>(&session), *reinterpret_cast<hstring const*>(&channelName), *reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const*>(&reliability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionOptions> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionOptions>
{
    int32_t WINRT_CALL get_IsInviteOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInviteOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInviteOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInviteOnly(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInviteOnly, WINRT_WRAP(void), bool);
            this->shim().IsInviteOnly(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipant> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipant>
{
    int32_t WINRT_CALL get_RemoteSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystem, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystem));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHostNames(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHostNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>>(this->shim().GetHostNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs>
{
    int32_t WINRT_CALL get_Participant(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Participant, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipant));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs>
{
    int32_t WINRT_CALL get_Participant(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Participant, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipant));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Participant());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher>
{
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

    int32_t WINRT_CALL get_Status(Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs>
{
    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionInfo));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionStatics>
{
    int32_t WINRT_CALL CreateWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionWatcher));
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs>
{
    int32_t WINRT_CALL get_SessionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInfo, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionInfo));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs>
{
    int32_t WINRT_CALL get_Sender(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sender, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionParticipant));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionParticipant>(this->shim().Sender());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemSessionWatcher> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemSessionWatcher>
{
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

    int32_t WINRT_CALL get_Status(Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemSessionWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemSessionWatcher, Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemStatics> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemStatics>
{
    int32_t WINRT_CALL FindByHostNameAsync(void* hostName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindByHostNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem>), Windows::Networking::HostName const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem>>(this->shim().FindByHostNameAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWatcher));
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherWithFilters(void* filters, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWatcher), Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcher(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const*>(&filters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemStatics2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemStatics2>
{
    int32_t WINRT_CALL IsAuthorizationKindEnabled(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind kind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAuthorizationKindEnabled, WINRT_WRAP(bool), Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const&);
            *result = detach_from<bool>(this->shim().IsAuthorizationKindEnabled(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemStatics3> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemStatics3>
{
    int32_t WINRT_CALL CreateWatcherForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcherForUser, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWatcher), Windows::System::User const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcherForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherWithFiltersForUser(void* user, void* filters, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcherForUser, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWatcher), Windows::System::User const&, Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const&);
            *result = detach_from<Windows::System::RemoteSystems::RemoteSystemWatcher>(this->shim().CreateWatcherForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const*>(&filters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter>
{
    int32_t WINRT_CALL get_RemoteSystemStatusType(Windows::System::RemoteSystems::RemoteSystemStatusType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemStatusType, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemStatusType));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemStatusType>(this->shim().RemoteSystemStatusType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory>
{
    int32_t WINRT_CALL Create(Windows::System::RemoteSystems::RemoteSystemStatusType remoteSystemStatusType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter), Windows::System::RemoteSystems::RemoteSystemStatusType const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter>(this->shim().Create(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemStatusType const*>(&remoteSystemStatusType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs>
{
    int32_t WINRT_CALL get_RemoteSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystem, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystem));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystem>(this->shim().RemoteSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWatcher> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWatcher>
{
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

    int32_t WINRT_CALL add_RemoteSystemAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemoteSystemAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemoteSystemAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemoteSystemAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RemoteSystemUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemoteSystemUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemoteSystemUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemoteSystemUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RemoteSystemRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteSystemRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemoteSystemRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemoteSystemRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemoteSystemRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemoteSystemRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWatcher2> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWatcher2>
{
    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::RemoteSystems::RemoteSystemWatcher, Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWatcher3> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWatcher3>
{
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
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs>
{
    int32_t WINRT_CALL get_Error(Windows::System::RemoteSystems::RemoteSystemWatcherError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWatcherError));
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemWatcherError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter>
{
    int32_t WINRT_CALL get_Account(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Account, WINRT_WRAP(Windows::Security::Credentials::WebAccount));
            *value = detach_from<Windows::Security::Credentials::WebAccount>(this->shim().Account());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory> : produce_base<D, Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory>
{
    int32_t WINRT_CALL Create(void* account, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::System::RemoteSystems::RemoteSystemWebAccountFilter), Windows::Security::Credentials::WebAccount const&);
            *value = detach_from<Windows::System::RemoteSystems::RemoteSystemWebAccountFilter>(this->shim().Create(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&account)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::RemoteSystems {

inline hstring KnownRemoteSystemCapabilities::AppService()
{
    return impl::call_factory<KnownRemoteSystemCapabilities, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>([&](auto&& f) { return f.AppService(); });
}

inline hstring KnownRemoteSystemCapabilities::LaunchUri()
{
    return impl::call_factory<KnownRemoteSystemCapabilities, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>([&](auto&& f) { return f.LaunchUri(); });
}

inline hstring KnownRemoteSystemCapabilities::RemoteSession()
{
    return impl::call_factory<KnownRemoteSystemCapabilities, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>([&](auto&& f) { return f.RemoteSession(); });
}

inline hstring KnownRemoteSystemCapabilities::SpatialEntity()
{
    return impl::call_factory<KnownRemoteSystemCapabilities, Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics>([&](auto&& f) { return f.SpatialEntity(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem> RemoteSystem::FindByHostNameAsync(Windows::Networking::HostName const& hostName)
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics>([&](auto&& f) { return f.FindByHostNameAsync(hostName); });
}

inline Windows::System::RemoteSystems::RemoteSystemWatcher RemoteSystem::CreateWatcher()
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics>([&](auto&& f) { return f.CreateWatcher(); });
}

inline Windows::System::RemoteSystems::RemoteSystemWatcher RemoteSystem::CreateWatcher(param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters)
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics>([&](auto&& f) { return f.CreateWatcher(filters); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus> RemoteSystem::RequestAccessAsync()
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline bool RemoteSystem::IsAuthorizationKindEnabled(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& kind)
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics2>([&](auto&& f) { return f.IsAuthorizationKindEnabled(kind); });
}

inline Windows::System::RemoteSystems::RemoteSystemWatcher RemoteSystem::CreateWatcherForUser(Windows::System::User const& user)
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics3>([&](auto&& f) { return f.CreateWatcherForUser(user); });
}

inline Windows::System::RemoteSystems::RemoteSystemWatcher RemoteSystem::CreateWatcherForUser(Windows::System::User const& user, param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters)
{
    return impl::call_factory<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystemStatics3>([&](auto&& f) { return f.CreateWatcherForUser(user, filters); });
}

inline Windows::System::RemoteSystems::RemoteSystemAppRegistration RemoteSystemAppRegistration::GetDefault()
{
    return impl::call_factory<RemoteSystemAppRegistration, Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::System::RemoteSystems::RemoteSystemAppRegistration RemoteSystemAppRegistration::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<RemoteSystemAppRegistration, Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline RemoteSystemAuthorizationKindFilter::RemoteSystemAuthorizationKindFilter(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& remoteSystemAuthorizationKind) :
    RemoteSystemAuthorizationKindFilter(impl::call_factory<RemoteSystemAuthorizationKindFilter, Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory>([&](auto&& f) { return f.Create(remoteSystemAuthorizationKind); }))
{}

inline Windows::System::RemoteSystems::RemoteSystemConnectionInfo RemoteSystemConnectionInfo::TryCreateFromAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& connection)
{
    return impl::call_factory<RemoteSystemConnectionInfo, Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics>([&](auto&& f) { return f.TryCreateFromAppServiceConnection(connection); });
}

inline RemoteSystemConnectionRequest::RemoteSystemConnectionRequest(Windows::System::RemoteSystems::RemoteSystem const& remoteSystem) :
    RemoteSystemConnectionRequest(impl::call_factory<RemoteSystemConnectionRequest, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory>([&](auto&& f) { return f.Create(remoteSystem); }))
{}

inline Windows::System::RemoteSystems::RemoteSystemConnectionRequest RemoteSystemConnectionRequest::CreateForApp(Windows::System::RemoteSystems::RemoteSystemApp const& remoteSystemApp)
{
    return impl::call_factory<RemoteSystemConnectionRequest, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics>([&](auto&& f) { return f.CreateForApp(remoteSystemApp); });
}

inline Windows::System::RemoteSystems::RemoteSystemConnectionRequest RemoteSystemConnectionRequest::CreateFromConnectionToken(param::hstring const& connectionToken)
{
    return impl::call_factory<RemoteSystemConnectionRequest, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2>([&](auto&& f) { return f.CreateFromConnectionToken(connectionToken); });
}

inline Windows::System::RemoteSystems::RemoteSystemConnectionRequest RemoteSystemConnectionRequest::CreateFromConnectionTokenForUser(Windows::System::User const& user, param::hstring const& connectionToken)
{
    return impl::call_factory<RemoteSystemConnectionRequest, Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2>([&](auto&& f) { return f.CreateFromConnectionTokenForUser(user, connectionToken); });
}

inline RemoteSystemDiscoveryTypeFilter::RemoteSystemDiscoveryTypeFilter(Windows::System::RemoteSystems::RemoteSystemDiscoveryType const& discoveryType) :
    RemoteSystemDiscoveryTypeFilter(impl::call_factory<RemoteSystemDiscoveryTypeFilter, Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory>([&](auto&& f) { return f.Create(discoveryType); }))
{}

inline RemoteSystemKindFilter::RemoteSystemKindFilter(param::iterable<hstring> const& remoteSystemKinds) :
    RemoteSystemKindFilter(impl::call_factory<RemoteSystemKindFilter, Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory>([&](auto&& f) { return f.Create(remoteSystemKinds); }))
{}

inline hstring RemoteSystemKinds::Phone()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics>([&](auto&& f) { return f.Phone(); });
}

inline hstring RemoteSystemKinds::Hub()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics>([&](auto&& f) { return f.Hub(); });
}

inline hstring RemoteSystemKinds::Holographic()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics>([&](auto&& f) { return f.Holographic(); });
}

inline hstring RemoteSystemKinds::Desktop()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics>([&](auto&& f) { return f.Desktop(); });
}

inline hstring RemoteSystemKinds::Xbox()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics>([&](auto&& f) { return f.Xbox(); });
}

inline hstring RemoteSystemKinds::Iot()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics2>([&](auto&& f) { return f.Iot(); });
}

inline hstring RemoteSystemKinds::Tablet()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics2>([&](auto&& f) { return f.Tablet(); });
}

inline hstring RemoteSystemKinds::Laptop()
{
    return impl::call_factory<RemoteSystemKinds, Windows::System::RemoteSystems::IRemoteSystemKindStatics2>([&](auto&& f) { return f.Laptop(); });
}

inline Windows::System::RemoteSystems::RemoteSystemSessionWatcher RemoteSystemSession::CreateWatcher()
{
    return impl::call_factory<RemoteSystemSession, Windows::System::RemoteSystems::IRemoteSystemSessionStatics>([&](auto&& f) { return f.CreateWatcher(); });
}

inline RemoteSystemSessionController::RemoteSystemSessionController(param::hstring const& displayName) :
    RemoteSystemSessionController(impl::call_factory<RemoteSystemSessionController, Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory>([&](auto&& f) { return f.CreateController(displayName); }))
{}

inline RemoteSystemSessionController::RemoteSystemSessionController(param::hstring const& displayName, Windows::System::RemoteSystems::RemoteSystemSessionOptions const& options) :
    RemoteSystemSessionController(impl::call_factory<RemoteSystemSessionController, Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory>([&](auto&& f) { return f.CreateController(displayName, options); }))
{}

inline RemoteSystemSessionInvitationListener::RemoteSystemSessionInvitationListener() :
    RemoteSystemSessionInvitationListener(impl::call_factory<RemoteSystemSessionInvitationListener>([](auto&& f) { return f.template ActivateInstance<RemoteSystemSessionInvitationListener>(); }))
{}

inline RemoteSystemSessionMessageChannel::RemoteSystemSessionMessageChannel(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName) :
    RemoteSystemSessionMessageChannel(impl::call_factory<RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory>([&](auto&& f) { return f.Create(session, channelName); }))
{}

inline RemoteSystemSessionMessageChannel::RemoteSystemSessionMessageChannel(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName, Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const& reliability) :
    RemoteSystemSessionMessageChannel(impl::call_factory<RemoteSystemSessionMessageChannel, Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory>([&](auto&& f) { return f.Create(session, channelName, reliability); }))
{}

inline RemoteSystemSessionOptions::RemoteSystemSessionOptions() :
    RemoteSystemSessionOptions(impl::call_factory<RemoteSystemSessionOptions>([](auto&& f) { return f.template ActivateInstance<RemoteSystemSessionOptions>(); }))
{}

inline RemoteSystemStatusTypeFilter::RemoteSystemStatusTypeFilter(Windows::System::RemoteSystems::RemoteSystemStatusType const& remoteSystemStatusType) :
    RemoteSystemStatusTypeFilter(impl::call_factory<RemoteSystemStatusTypeFilter, Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory>([&](auto&& f) { return f.Create(remoteSystemStatusType); }))
{}

inline RemoteSystemWebAccountFilter::RemoteSystemWebAccountFilter(Windows::Security::Credentials::WebAccount const& account) :
    RemoteSystemWebAccountFilter(impl::call_factory<RemoteSystemWebAccountFilter, Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory>([&](auto&& f) { return f.Create(account); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IKnownRemoteSystemCapabilitiesStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem3> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem3> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem4> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem4> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem5> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem5> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystem6> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystem6> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemApp> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemApp> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemApp2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemApp2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistration> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemAppRegistrationStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilterFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfo> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionInfoStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemConnectionRequestStatics2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilterFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemKindFilterFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemKindStatics2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSession> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSession> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionController> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionControllerFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInfo> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitation> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannelFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionOptions> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipant> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemSessionWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemStatics3> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilterFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher2> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcher3> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::IRemoteSystemWebAccountFilterFactory> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::KnownRemoteSystemCapabilities> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::KnownRemoteSystemCapabilities> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystem> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystem> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemApp> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemApp> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemAppRegistration> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemAuthorizationKindFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionInfo> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemConnectionRequest> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemDiscoveryTypeFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemEnumerationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemKindFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemKinds> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemKinds> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSession> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSession> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionController> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionCreationResult> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionDisconnectedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInfo> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitation> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationListener> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionInvitationReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequest> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinRequestedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionJoinResult> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionMessageChannel> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionOptions> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipant> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantAddedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionParticipantWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionRemovedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionValueSetReceivedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemSessionWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemStatusTypeFilter> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemWatcher> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemWatcherErrorOccurredEventArgs> {};
template<> struct hash<winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter> : winrt::impl::hash_base<winrt::Windows::System::RemoteSystems::RemoteSystemWebAccountFilter> {};

}
