// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.AppService.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Networking.1.h"
#include "winrt/impl/Windows.Security.Credentials.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.System.RemoteSystems.1.h"

WINRT_EXPORT namespace winrt::Windows::System::RemoteSystems {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::RemoteSystems {

struct KnownRemoteSystemCapabilities
{
    KnownRemoteSystemCapabilities() = delete;
    static hstring AppService();
    static hstring LaunchUri();
    static hstring RemoteSession();
    static hstring SpatialEntity();
};

struct WINRT_EBO RemoteSystem :
    Windows::System::RemoteSystems::IRemoteSystem,
    impl::require<RemoteSystem, Windows::System::RemoteSystems::IRemoteSystem2, Windows::System::RemoteSystems::IRemoteSystem3, Windows::System::RemoteSystems::IRemoteSystem4, Windows::System::RemoteSystems::IRemoteSystem5, Windows::System::RemoteSystems::IRemoteSystem6>
{
    RemoteSystem(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystem> FindByHostNameAsync(Windows::Networking::HostName const& hostName);
    static Windows::System::RemoteSystems::RemoteSystemWatcher CreateWatcher();
    static Windows::System::RemoteSystems::RemoteSystemWatcher CreateWatcher(param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters);
    static Windows::Foundation::IAsyncOperation<Windows::System::RemoteSystems::RemoteSystemAccessStatus> RequestAccessAsync();
    static bool IsAuthorizationKindEnabled(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& kind);
    static Windows::System::RemoteSystems::RemoteSystemWatcher CreateWatcherForUser(Windows::System::User const& user);
    static Windows::System::RemoteSystems::RemoteSystemWatcher CreateWatcherForUser(Windows::System::User const& user, param::iterable<Windows::System::RemoteSystems::IRemoteSystemFilter> const& filters);
};

struct WINRT_EBO RemoteSystemAddedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemAddedEventArgs
{
    RemoteSystemAddedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemApp :
    Windows::System::RemoteSystems::IRemoteSystemApp,
    impl::require<RemoteSystemApp, Windows::System::RemoteSystems::IRemoteSystemApp2>
{
    RemoteSystemApp(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemAppRegistration :
    Windows::System::RemoteSystems::IRemoteSystemAppRegistration
{
    RemoteSystemAppRegistration(std::nullptr_t) noexcept {}
    static Windows::System::RemoteSystems::RemoteSystemAppRegistration GetDefault();
    static Windows::System::RemoteSystems::RemoteSystemAppRegistration GetForUser(Windows::System::User const& user);
};

struct WINRT_EBO RemoteSystemAuthorizationKindFilter :
    Windows::System::RemoteSystems::IRemoteSystemAuthorizationKindFilter,
    impl::require<RemoteSystemAuthorizationKindFilter, Windows::System::RemoteSystems::IRemoteSystemFilter>
{
    RemoteSystemAuthorizationKindFilter(std::nullptr_t) noexcept {}
    RemoteSystemAuthorizationKindFilter(Windows::System::RemoteSystems::RemoteSystemAuthorizationKind const& remoteSystemAuthorizationKind);
};

struct WINRT_EBO RemoteSystemConnectionInfo :
    Windows::System::RemoteSystems::IRemoteSystemConnectionInfo
{
    RemoteSystemConnectionInfo(std::nullptr_t) noexcept {}
    static Windows::System::RemoteSystems::RemoteSystemConnectionInfo TryCreateFromAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& connection);
};

struct WINRT_EBO RemoteSystemConnectionRequest :
    Windows::System::RemoteSystems::IRemoteSystemConnectionRequest,
    impl::require<RemoteSystemConnectionRequest, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest2, Windows::System::RemoteSystems::IRemoteSystemConnectionRequest3>
{
    RemoteSystemConnectionRequest(std::nullptr_t) noexcept {}
    RemoteSystemConnectionRequest(Windows::System::RemoteSystems::RemoteSystem const& remoteSystem);
    static Windows::System::RemoteSystems::RemoteSystemConnectionRequest CreateForApp(Windows::System::RemoteSystems::RemoteSystemApp const& remoteSystemApp);
    static Windows::System::RemoteSystems::RemoteSystemConnectionRequest CreateFromConnectionToken(param::hstring const& connectionToken);
    static Windows::System::RemoteSystems::RemoteSystemConnectionRequest CreateFromConnectionTokenForUser(Windows::System::User const& user, param::hstring const& connectionToken);
};

struct WINRT_EBO RemoteSystemDiscoveryTypeFilter :
    Windows::System::RemoteSystems::IRemoteSystemDiscoveryTypeFilter,
    impl::require<RemoteSystemDiscoveryTypeFilter, Windows::System::RemoteSystems::IRemoteSystemFilter>
{
    RemoteSystemDiscoveryTypeFilter(std::nullptr_t) noexcept {}
    RemoteSystemDiscoveryTypeFilter(Windows::System::RemoteSystems::RemoteSystemDiscoveryType const& discoveryType);
};

struct WINRT_EBO RemoteSystemEnumerationCompletedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemEnumerationCompletedEventArgs
{
    RemoteSystemEnumerationCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemKindFilter :
    Windows::System::RemoteSystems::IRemoteSystemKindFilter,
    impl::require<RemoteSystemKindFilter, Windows::System::RemoteSystems::IRemoteSystemFilter>
{
    RemoteSystemKindFilter(std::nullptr_t) noexcept {}
    RemoteSystemKindFilter(param::iterable<hstring> const& remoteSystemKinds);
};

struct RemoteSystemKinds
{
    RemoteSystemKinds() = delete;
    static hstring Phone();
    static hstring Hub();
    static hstring Holographic();
    static hstring Desktop();
    static hstring Xbox();
    static hstring Iot();
    static hstring Tablet();
    static hstring Laptop();
};

struct WINRT_EBO RemoteSystemRemovedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemRemovedEventArgs
{
    RemoteSystemRemovedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSession :
    Windows::System::RemoteSystems::IRemoteSystemSession,
    impl::require<RemoteSystemSession, Windows::Foundation::IClosable>
{
    RemoteSystemSession(std::nullptr_t) noexcept {}
    static Windows::System::RemoteSystems::RemoteSystemSessionWatcher CreateWatcher();
};

struct WINRT_EBO RemoteSystemSessionAddedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionAddedEventArgs
{
    RemoteSystemSessionAddedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionController :
    Windows::System::RemoteSystems::IRemoteSystemSessionController
{
    RemoteSystemSessionController(std::nullptr_t) noexcept {}
    RemoteSystemSessionController(param::hstring const& displayName);
    RemoteSystemSessionController(param::hstring const& displayName, Windows::System::RemoteSystems::RemoteSystemSessionOptions const& options);
};

struct WINRT_EBO RemoteSystemSessionCreationResult :
    Windows::System::RemoteSystems::IRemoteSystemSessionCreationResult
{
    RemoteSystemSessionCreationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionDisconnectedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionDisconnectedEventArgs
{
    RemoteSystemSessionDisconnectedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionInfo :
    Windows::System::RemoteSystems::IRemoteSystemSessionInfo
{
    RemoteSystemSessionInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionInvitation :
    Windows::System::RemoteSystems::IRemoteSystemSessionInvitation
{
    RemoteSystemSessionInvitation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionInvitationListener :
    Windows::System::RemoteSystems::IRemoteSystemSessionInvitationListener
{
    RemoteSystemSessionInvitationListener(std::nullptr_t) noexcept {}
    RemoteSystemSessionInvitationListener();
};

struct WINRT_EBO RemoteSystemSessionInvitationReceivedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionInvitationReceivedEventArgs
{
    RemoteSystemSessionInvitationReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionJoinRequest :
    Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequest
{
    RemoteSystemSessionJoinRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionJoinRequestedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionJoinRequestedEventArgs
{
    RemoteSystemSessionJoinRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionJoinResult :
    Windows::System::RemoteSystems::IRemoteSystemSessionJoinResult
{
    RemoteSystemSessionJoinResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionMessageChannel :
    Windows::System::RemoteSystems::IRemoteSystemSessionMessageChannel
{
    RemoteSystemSessionMessageChannel(std::nullptr_t) noexcept {}
    RemoteSystemSessionMessageChannel(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName);
    RemoteSystemSessionMessageChannel(Windows::System::RemoteSystems::RemoteSystemSession const& session, param::hstring const& channelName, Windows::System::RemoteSystems::RemoteSystemSessionMessageChannelReliability const& reliability);
};

struct WINRT_EBO RemoteSystemSessionOptions :
    Windows::System::RemoteSystems::IRemoteSystemSessionOptions
{
    RemoteSystemSessionOptions(std::nullptr_t) noexcept {}
    RemoteSystemSessionOptions();
};

struct WINRT_EBO RemoteSystemSessionParticipant :
    Windows::System::RemoteSystems::IRemoteSystemSessionParticipant
{
    RemoteSystemSessionParticipant(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionParticipantAddedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionParticipantAddedEventArgs
{
    RemoteSystemSessionParticipantAddedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionParticipantRemovedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionParticipantRemovedEventArgs
{
    RemoteSystemSessionParticipantRemovedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionParticipantWatcher :
    Windows::System::RemoteSystems::IRemoteSystemSessionParticipantWatcher
{
    RemoteSystemSessionParticipantWatcher(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionRemovedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionRemovedEventArgs
{
    RemoteSystemSessionRemovedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionUpdatedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionUpdatedEventArgs
{
    RemoteSystemSessionUpdatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionValueSetReceivedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemSessionValueSetReceivedEventArgs
{
    RemoteSystemSessionValueSetReceivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemSessionWatcher :
    Windows::System::RemoteSystems::IRemoteSystemSessionWatcher
{
    RemoteSystemSessionWatcher(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemStatusTypeFilter :
    Windows::System::RemoteSystems::IRemoteSystemStatusTypeFilter,
    impl::require<RemoteSystemStatusTypeFilter, Windows::System::RemoteSystems::IRemoteSystemFilter>
{
    RemoteSystemStatusTypeFilter(std::nullptr_t) noexcept {}
    RemoteSystemStatusTypeFilter(Windows::System::RemoteSystems::RemoteSystemStatusType const& remoteSystemStatusType);
};

struct WINRT_EBO RemoteSystemUpdatedEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemUpdatedEventArgs
{
    RemoteSystemUpdatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemWatcher :
    Windows::System::RemoteSystems::IRemoteSystemWatcher,
    impl::require<RemoteSystemWatcher, Windows::System::RemoteSystems::IRemoteSystemWatcher2, Windows::System::RemoteSystems::IRemoteSystemWatcher3>
{
    RemoteSystemWatcher(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemWatcherErrorOccurredEventArgs :
    Windows::System::RemoteSystems::IRemoteSystemWatcherErrorOccurredEventArgs
{
    RemoteSystemWatcherErrorOccurredEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RemoteSystemWebAccountFilter :
    Windows::System::RemoteSystems::IRemoteSystemWebAccountFilter,
    impl::require<RemoteSystemWebAccountFilter, Windows::System::RemoteSystems::IRemoteSystemFilter>
{
    RemoteSystemWebAccountFilter(std::nullptr_t) noexcept {}
    RemoteSystemWebAccountFilter(Windows::Security::Credentials::WebAccount const& account);
};

}
