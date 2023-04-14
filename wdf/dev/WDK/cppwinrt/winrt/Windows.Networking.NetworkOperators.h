// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Devices.Sms.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Networking.NetworkOperators.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IESim<D>::AvailableMemoryInBytes() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_AvailableMemoryInBytes(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESim<D>::Eid() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_Eid(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESim<D>::FirmwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_FirmwareVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESim<D>::MobileBroadbandModemDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_MobileBroadbandModemDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimPolicy consume_Windows_Networking_NetworkOperators_IESim<D>::Policy() const
{
    Windows::Networking::NetworkOperators::ESimPolicy value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_Policy(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimState consume_Windows_Networking_NetworkOperators_IESim<D>::State() const
{
    Windows::Networking::NetworkOperators::ESimState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimProfile> consume_Windows_Networking_NetworkOperators_IESim<D>::GetProfiles() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimProfile> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->GetProfiles(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESim<D>::DeleteProfileAsync(param::hstring const& profileId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->DeleteProfileAsync(get_abi(profileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult> consume_Windows_Networking_NetworkOperators_IESim<D>::DownloadProfileMetadataAsync(param::hstring const& activationCode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->DownloadProfileMetadataAsync(get_abi(activationCode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESim<D>::ResetAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->ResetAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESim<D>::ProfileChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->add_ProfileChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESim<D>::ProfileChanged_revoker consume_Windows_Networking_NetworkOperators_IESim<D>::ProfileChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ProfileChanged_revoker>(this, ProfileChanged(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESim<D>::ProfileChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESim)->remove_ProfileChanged(get_abi(token)));
}

template <typename D> Windows::Networking::NetworkOperators::ESimDiscoverResult consume_Windows_Networking_NetworkOperators_IESim2<D>::Discover() const
{
    Windows::Networking::NetworkOperators::ESimDiscoverResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim2)->Discover(put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::NetworkOperators::ESimDiscoverResult consume_Windows_Networking_NetworkOperators_IESim2<D>::Discover(param::hstring const& serverAddress, param::hstring const& matchingId) const
{
    Windows::Networking::NetworkOperators::ESimDiscoverResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim2)->DiscoverWithServerAddressAndMatchingId(get_abi(serverAddress), get_abi(matchingId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> consume_Windows_Networking_NetworkOperators_IESim2<D>::DiscoverAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim2)->DiscoverAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> consume_Windows_Networking_NetworkOperators_IESim2<D>::DiscoverAsync(param::hstring const& serverAddress, param::hstring const& matchingId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESim2)->DiscoverWithServerAddressAndMatchingIdAsync(get_abi(serverAddress), get_abi(matchingId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::NetworkOperators::ESim consume_Windows_Networking_NetworkOperators_IESimAddedEventArgs<D>::ESim() const
{
    Windows::Networking::NetworkOperators::ESim value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimAddedEventArgs)->get_ESim(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimDiscoverEvent<D>::MatchingId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverEvent)->get_MatchingId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimDiscoverEvent<D>::RspServerAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverEvent)->get_RspServerAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimDiscoverEvent> consume_Windows_Networking_NetworkOperators_IESimDiscoverResult<D>::Events() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimDiscoverEvent> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverResult)->get_Events(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimDiscoverResultKind consume_Windows_Networking_NetworkOperators_IESimDiscoverResult<D>::Kind() const
{
    Windows::Networking::NetworkOperators::ESimDiscoverResultKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverResult)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfileMetadata consume_Windows_Networking_NetworkOperators_IESimDiscoverResult<D>::ProfileMetadata() const
{
    Windows::Networking::NetworkOperators::ESimProfileMetadata value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverResult)->get_ProfileMetadata(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimOperationResult consume_Windows_Networking_NetworkOperators_IESimDiscoverResult<D>::Result() const
{
    Windows::Networking::NetworkOperators::ESimOperationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDiscoverResult)->get_Result(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimOperationResult consume_Windows_Networking_NetworkOperators_IESimDownloadProfileMetadataResult<D>::Result() const
{
    Windows::Networking::NetworkOperators::ESimOperationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult)->get_Result(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfileMetadata consume_Windows_Networking_NetworkOperators_IESimDownloadProfileMetadataResult<D>::ProfileMetadata() const
{
    Windows::Networking::NetworkOperators::ESimProfileMetadata value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult)->get_ProfileMetadata(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimServiceInfo consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::ServiceInfo() const
{
    Windows::Networking::NetworkOperators::ESimServiceInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimManagerStatics)->get_ServiceInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimWatcher consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::TryCreateESimWatcher() const
{
    Windows::Networking::NetworkOperators::ESimWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimManagerStatics)->TryCreateESimWatcher(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::ServiceInfoChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimManagerStatics)->add_ServiceInfoChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::ServiceInfoChanged_revoker consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::ServiceInfoChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ServiceInfoChanged_revoker>(this, ServiceInfoChanged(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimManagerStatics<D>::ServiceInfoChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimManagerStatics)->remove_ServiceInfoChanged(get_abi(token)));
}

template <typename D> Windows::Networking::NetworkOperators::ESimOperationStatus consume_Windows_Networking_NetworkOperators_IESimOperationResult<D>::Status() const
{
    Windows::Networking::NetworkOperators::ESimOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimOperationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimPolicy<D>::ShouldEnableManagingUi() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimPolicy)->get_ShouldEnableManagingUi(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfileClass consume_Windows_Networking_NetworkOperators_IESimProfile<D>::Class() const
{
    Windows::Networking::NetworkOperators::ESimProfileClass value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_Class(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfile<D>::Nickname() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_Nickname(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfilePolicy consume_Windows_Networking_NetworkOperators_IESimProfile<D>::Policy() const
{
    Windows::Networking::NetworkOperators::ESimProfilePolicy value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_Policy(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfile<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Networking_NetworkOperators_IESimProfile<D>::ProviderIcon() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_ProviderIcon(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfile<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfile<D>::ProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_ProviderName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfileState consume_Windows_Networking_NetworkOperators_IESimProfile<D>::State() const
{
    Windows::Networking::NetworkOperators::ESimProfileState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESimProfile<D>::DisableAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->DisableAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESimProfile<D>::EnableAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->EnableAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESimProfile<D>::SetNicknameAsync(param::hstring const& newNickname) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfile)->SetNicknameAsync(get_abi(newNickname), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::IsConfirmationCodeRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_IsConfirmationCodeRequired(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfilePolicy consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::Policy() const
{
    Windows::Networking::NetworkOperators::ESimProfilePolicy value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_Policy(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::ProviderIcon() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_ProviderIcon(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::ProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_ProviderName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimProfileMetadataState consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::State() const
{
    Windows::Networking::NetworkOperators::ESimProfileMetadataState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::DenyInstallAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->DenyInstallAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::ConfirmInstallAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->ConfirmInstallAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::ConfirmInstallAsync(param::hstring const& confirmationCode) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->ConfirmInstallWithConfirmationCodeAsync(get_abi(confirmationCode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::PostponeInstallAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->PostponeInstallAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::StateChanged_revoker consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimProfileMetadata<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfileMetadata)->remove_StateChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimProfilePolicy<D>::CanDelete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfilePolicy)->get_CanDelete(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimProfilePolicy<D>::CanDisable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfilePolicy)->get_CanDisable(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimProfilePolicy<D>::IsManagedByEnterprise() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimProfilePolicy)->get_IsManagedByEnterprise(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESim consume_Windows_Networking_NetworkOperators_IESimRemovedEventArgs<D>::ESim() const
{
    Windows::Networking::NetworkOperators::ESim value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimRemovedEventArgs)->get_ESim(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimAuthenticationPreference consume_Windows_Networking_NetworkOperators_IESimServiceInfo<D>::AuthenticationPreference() const
{
    Windows::Networking::NetworkOperators::ESimAuthenticationPreference value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimServiceInfo)->get_AuthenticationPreference(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IESimServiceInfo<D>::IsESimUiEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimServiceInfo)->get_IsESimUiEnabled(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESim consume_Windows_Networking_NetworkOperators_IESimUpdatedEventArgs<D>::ESim() const
{
    Windows::Networking::NetworkOperators::ESim value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimUpdatedEventArgs)->get_ESim(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::ESimWatcherStatus consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Status() const
{
    Windows::Networking::NetworkOperators::ESimWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->Start());
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Added_revoker consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Removed_revoker consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Stopped_revoker consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Updated_revoker consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IESimWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IESimWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Networking_NetworkOperators_IFdnAccessManagerStatics<D>::RequestUnlockAsync(param::hstring const& contactListId) const
{
    Windows::Foundation::IAsyncOperation<bool> returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IFdnAccessManagerStatics)->RequestUnlockAsync(get_abi(contactListId), put_abi(returnValue)));
    return returnValue;
}

template <typename D> com_array<uint8_t> consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::WirelessNetworkId() const
{
    com_array<uint8_t> value;
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->get_WirelessNetworkId(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkAdapter consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::NetworkAdapter() const
{
    Windows::Networking::Connectivity::NetworkAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->get_NetworkAdapter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::RedirectMessageUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->get_RedirectMessageUrl(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::RedirectMessageXml() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->get_RedirectMessageXml(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::AuthenticationUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->get_AuthenticationUrl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::IssueCredentials(param::hstring const& userName, param::hstring const& password, param::hstring const& extraParameters, bool markAsManualConnectOnFailure) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->IssueCredentials(get_abi(userName), get_abi(password), get_abi(extraParameters), markAsManualConnectOnFailure));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::AbortAuthentication(bool markAsManual) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->AbortAuthentication(markAsManual));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::SkipAuthentication() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->SkipAuthentication());
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext<D>::TriggerAttentionRequired(param::hstring const& packageRelativeApplicationId, param::hstring const& applicationParameters) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext)->TriggerAttentionRequired(get_abi(packageRelativeApplicationId), get_abi(applicationParameters)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult> consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContext2<D>::IssueCredentialsAsync(param::hstring const& userName, param::hstring const& password, param::hstring const& extraParameters, bool markAsManualConnectOnFailure) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2)->IssueCredentialsAsync(get_abi(userName), get_abi(password), get_abi(extraParameters), markAsManualConnectOnFailure, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationContextStatics<D>::TryGetAuthenticationContext(param::hstring const& evenToken, Windows::Networking::NetworkOperators::HotspotAuthenticationContext& context) const
{
    bool isValid{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics)->TryGetAuthenticationContext(get_abi(evenToken), put_abi(context), &isValid));
    return isValid;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IHotspotAuthenticationEventDetails<D>::EventToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails)->get_EventToken(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult<D>::HasNetworkErrorOccurred() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult)->get_HasNetworkErrorOccurred(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult<D>::ResponseCode() const
{
    Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult)->get_ResponseCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult<D>::LogoffUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult)->get_LogoffUrl(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Xml::Dom::XmlDocument consume_Windows_Networking_NetworkOperators_IHotspotCredentialsAuthenticationResult<D>::AuthenticationReplyXml() const
{
    Windows::Data::Xml::Dom::XmlDocument value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult)->get_AuthenticationReplyXml(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownCSimFilePathsStatics<D>::EFSpn() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics)->get_EFSpn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownCSimFilePathsStatics<D>::Gid1() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics)->get_Gid1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownCSimFilePathsStatics<D>::Gid2() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics)->get_Gid2(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownRuimFilePathsStatics<D>::EFSpn() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics)->get_EFSpn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownRuimFilePathsStatics<D>::Gid1() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics)->get_Gid1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownRuimFilePathsStatics<D>::Gid2() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics)->get_Gid2(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics<D>::EFOns() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics)->get_EFOns(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics<D>::EFSpn() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics)->get_EFSpn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics<D>::Gid1() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics)->get_Gid1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownSimFilePathsStatics<D>::Gid2() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics)->get_Gid2(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>::EFSpn() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics)->get_EFSpn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>::EFOpl() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics)->get_EFOpl(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>::EFPnn() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics)->get_EFPnn(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>::Gid1() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics)->get_Gid1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IKnownUSimFilePathsStatics<D>::Gid2() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics)->get_Gid2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>::ServiceProviderGuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount)->get_ServiceProviderGuid(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>::ServiceProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount)->get_ServiceProviderName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandNetwork consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>::CurrentNetwork() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork network{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount)->get_CurrentNetwork(put_abi(network)));
    return network;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount<D>::CurrentDeviceInformation() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation deviceInformation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount)->get_CurrentDeviceInformation(put_abi(deviceInformation)));
    return deviceInformation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount2<D>::GetConnectionProfiles() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount2)->GetConnectionProfiles(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccount3<D>::AccountExperienceUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccount3)->get_AccountExperienceUrl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountEventArgs<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountStatics<D>::AvailableNetworkAccountIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> ppAccountIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics)->get_AvailableNetworkAccountIds(put_abi(ppAccountIds)));
    return ppAccountIds;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandAccount consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountStatics<D>::CreateFromNetworkAccountId(param::hstring const& networkAccountId) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandAccount ppAccount{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics)->CreateFromNetworkAccountId(get_abi(networkAccountId), put_abi(ppAccount)));
    return ppAccount;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountUpdatedEventArgs<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountUpdatedEventArgs<D>::HasDeviceInformationChanged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs)->get_HasDeviceInformationChanged(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountUpdatedEventArgs<D>::HasNetworkChanged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs)->get_HasNetworkChanged(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountAdded(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->add_AccountAdded(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountAdded_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccountAdded_revoker>(this, AccountAdded(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountAdded(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->remove_AccountAdded(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountUpdated(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->add_AccountUpdated(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountUpdated_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccountUpdated_revoker>(this, AccountUpdated(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountUpdated(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->remove_AccountUpdated(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountRemoved(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->add_AccountRemoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountRemoved_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccountRemoved_revoker>(this, AccountRemoved(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::AccountRemoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->remove_AccountRemoved(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::EnumerationCompleted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->remove_EnumerationCompleted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->add_Stopped(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Stopped_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Stopped(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->remove_Stopped(get_abi(cookie)));
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Status() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->Start());
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandAccountWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher)->Stop());
}

template <typename D> int32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSar<D>::AntennaIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar)->get_AntennaIndex(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSar<D>::SarBackoffIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar)->get_SarBackoffIndex(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar consume_Windows_Networking_NetworkOperators_IMobileBroadbandAntennaSarFactory<D>::CreateWithIndex(int32_t antennaIndex, int32_t sarBackoffIndex) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar antennaSar{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory)->CreateWithIndex(antennaIndex, sarBackoffIndex, put_abi(antennaSar)));
    return antennaSar;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::BaseStationId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_BaseStationId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::BaseStationPNCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_BaseStationPNCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::BaseStationLatitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_BaseStationLatitude(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::BaseStationLongitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_BaseStationLongitude(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::BaseStationLastBroadcastGpsTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_BaseStationLastBroadcastGpsTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::NetworkId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_NetworkId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::PilotSignalStrengthInDB() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_PilotSignalStrengthInDB(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellCdma<D>::SystemId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma)->get_SystemId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::BaseStationId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_BaseStationId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::CellId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_CellId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::ChannelNumber() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_ChannelNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::LocationAreaCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_LocationAreaCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::ReceivedSignalStrengthInDBm() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_ReceivedSignalStrengthInDBm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellGsm<D>::TimingAdvanceInBitPeriods() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm)->get_TimingAdvanceInBitPeriods(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::CellId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_CellId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::ChannelNumber() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_ChannelNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::PhysicalCellId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_PhysicalCellId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::ReferenceSignalReceivedPowerInDBm() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_ReferenceSignalReceivedPowerInDBm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::ReferenceSignalReceivedQualityInDBm() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_ReferenceSignalReceivedQualityInDBm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::TimingAdvanceInBitPeriods() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_TimingAdvanceInBitPeriods(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellLte<D>::TrackingAreaCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellLte)->get_TrackingAreaCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::CellId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_CellId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::CellParameterId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_CellParameterId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::ChannelNumber() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_ChannelNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::LocationAreaCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_LocationAreaCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::PathLossInDB() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_PathLossInDB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::ReceivedSignalCodePowerInDBm() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_ReceivedSignalCodePowerInDBm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellTdscdma<D>::TimingAdvanceInBitPeriods() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma)->get_TimingAdvanceInBitPeriods(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::CellId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_CellId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::ChannelNumber() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_ChannelNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::LocationAreaCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_LocationAreaCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::PathLossInDB() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_PathLossInDB(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::PrimaryScramblingCode() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_PrimaryScramblingCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::ReceivedSignalCodePowerInDBm() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_ReceivedSignalCodePowerInDBm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellUmts<D>::SignalToNoiseRatioInDB() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts)->get_SignalToNoiseRatioInDB(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::NeighboringCellsCdma() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_NeighboringCellsCdma(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::NeighboringCellsGsm() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_NeighboringCellsGsm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::NeighboringCellsLte() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_NeighboringCellsLte(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::NeighboringCellsTdscdma() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_NeighboringCellsTdscdma(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::NeighboringCellsUmts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_NeighboringCellsUmts(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::ServingCellsCdma() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_ServingCellsCdma(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::ServingCellsGsm() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_ServingCellsGsm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::ServingCellsLte() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_ServingCellsLte(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::ServingCellsTdscdma() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_ServingCellsTdscdma(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> consume_Windows_Networking_NetworkOperators_IMobileBroadbandCellsInfo<D>::ServingCellsUmts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo)->get_ServingCellsUmts(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkDeviceStatus consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::NetworkDeviceStatus() const
{
    Windows::Networking::NetworkOperators::NetworkDeviceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_NetworkDeviceStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::Manufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_Manufacturer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::Model() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_Model(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::FirmwareInformation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_FirmwareInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::CellularClass consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::CellularClass() const
{
    Windows::Devices::Sms::CellularClass value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_CellularClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::DataClasses consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::DataClasses() const
{
    Windows::Networking::NetworkOperators::DataClasses value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_DataClasses(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::CustomDataClass() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_CustomDataClass(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::MobileEquipmentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_MobileEquipmentId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::TelephoneNumbers() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_TelephoneNumbers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::SubscriberId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_SubscriberId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::SimIccId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_SimIccId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceType consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::DeviceType() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceType pDeviceType{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_DeviceType(put_abi(pDeviceType)));
    return pDeviceType;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandRadioState consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation<D>::CurrentRadioState() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandRadioState pCurrentState{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation)->get_CurrentRadioState(put_abi(pCurrentState)));
    return pCurrentState;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinManager consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation2<D>::PinManager() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2)->get_PinManager(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation2<D>::Revision() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2)->get_Revision(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation2<D>::SerialNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2)->get_SerialNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation3<D>::SimSpn() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3)->get_SimSpn(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation3<D>::SimPnn() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3)->get_SimPnn(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceInformation3<D>::SimGid1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3)->get_SimGid1(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService<D>::DeviceServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService)->get_DeviceServiceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService<D>::SupportedCommands() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService)->get_SupportedCommands(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService<D>::OpenDataSession() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService)->OpenDataSession(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceService<D>::OpenCommandSession() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService)->OpenCommandSession(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandResult<D>::StatusCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult)->get_StatusCode(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandResult<D>::ResponseData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult)->get_ResponseData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandSession<D>::SendQueryCommandAsync(uint32_t commandId, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession)->SendQueryCommandAsync(commandId, get_abi(data), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandSession<D>::SendSetCommandAsync(uint32_t commandId, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession)->SendSetCommandAsync(commandId, get_abi(data), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceCommandSession<D>::CloseSession() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession)->CloseSession());
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataReceivedEventArgs<D>::ReceivedData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs)->get_ReceivedData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::WriteDataAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession)->WriteDataAsync(get_abi(value), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::CloseSession() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession)->CloseSession());
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::DataReceived(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession)->add_DataReceived(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::DataReceived_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::DataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, DataReceived_revoker>(this, DataReceived(eventHandler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceDataSession<D>::DataReceived(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession)->remove_DataReceived(get_abi(eventCookie)));
}

template <typename D> winrt::guid consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceInformation<D>::DeviceServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation)->get_DeviceServiceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceInformation<D>::IsDataReadSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation)->get_IsDataReadSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceInformation<D>::IsDataWriteSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation)->get_IsDataWriteSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceTriggerDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceTriggerDetails<D>::DeviceServiceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails)->get_DeviceServiceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandDeviceServiceTriggerDetails<D>::ReceivedData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails)->get_ReceivedData(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandAccount consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::CurrentAccount() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_CurrentAccount(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::DeviceInformation() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::MaxDeviceServiceCommandSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_MaxDeviceServiceCommandSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::MaxDeviceServiceDataSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_MaxDeviceServiceDataSizeInBytes(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation> consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::DeviceServices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_DeviceServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandDeviceService consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::GetDeviceService(winrt::guid const& deviceServiceId) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandDeviceService value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->GetDeviceService(get_abi(deviceServiceId), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::IsResetSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_IsResetSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::ResetAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->ResetAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration> consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::GetCurrentConfigurationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->GetCurrentConfigurationAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandNetwork consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem<D>::CurrentNetwork() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem)->get_CurrentNetwork(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem2<D>::GetIsPassthroughEnabledAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem2)->GetIsPassthroughEnabledAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus> consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem2<D>::SetIsPassthroughEnabledAsync(bool value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem2)->SetIsPassthroughEnabledAsync(value, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPco> consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::TryGetPcoAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPco> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem3)->TryGetPcoAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::IsInEmergencyCallMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem3)->get_IsInEmergencyCallMode(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::IsInEmergencyCallModeChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem3)->add_IsInEmergencyCallModeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::IsInEmergencyCallModeChanged_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::IsInEmergencyCallModeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsInEmergencyCallModeChanged_revoker>(this, IsInEmergencyCallModeChanged(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandModem3<D>::IsInEmergencyCallModeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModem3)->remove_IsInEmergencyCallModeChanged(get_abi(token)));
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandUicc consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration<D>::Uicc() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandUicc value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration)->get_Uicc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration<D>::HomeProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration)->get_HomeProviderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration<D>::HomeProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration)->get_HomeProviderName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandSarManager consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemConfiguration2<D>::SarManager() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandSarManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2)->get_SarManager(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation<D>::AddAllowedHost(Windows::Networking::HostName const& host) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation)->AddAllowedHost(get_abi(host)));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation<D>::AddAllowedHostRange(Windows::Networking::HostName const& first, Windows::Networking::HostName const& last) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation)->AddAllowedHostRange(get_abi(first), get_abi(last)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation<D>::ApplyConfigurationAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation)->ApplyConfigurationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolation<D>::ClearConfigurationAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation)->ClearConfigurationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemIsolationFactory<D>::Create(param::hstring const& modemDeviceId, param::hstring const& ruleGroupId) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory)->Create(get_abi(modemDeviceId), get_abi(ruleGroupId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandModem consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemStatics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandModem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics)->FromId(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandModem consume_Windows_Networking_NetworkOperators_IMobileBroadbandModemStatics<D>::GetDefault() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandModem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkAdapter consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::NetworkAdapter() const
{
    Windows::Networking::Connectivity::NetworkAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_NetworkAdapter(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkRegistrationState consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::NetworkRegistrationState() const
{
    Windows::Networking::NetworkOperators::NetworkRegistrationState registrationState{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_NetworkRegistrationState(put_abi(registrationState)));
    return registrationState;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::RegistrationNetworkError() const
{
    uint32_t networkError{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_RegistrationNetworkError(&networkError));
    return networkError;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::PacketAttachNetworkError() const
{
    uint32_t networkError{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_PacketAttachNetworkError(&networkError));
    return networkError;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::ActivationNetworkError() const
{
    uint32_t networkError{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_ActivationNetworkError(&networkError));
    return networkError;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::AccessPointName() const
{
    hstring apn{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_AccessPointName(put_abi(apn)));
    return apn;
}

template <typename D> Windows::Networking::NetworkOperators::DataClasses consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::RegisteredDataClass() const
{
    Windows::Networking::NetworkOperators::DataClasses value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_RegisteredDataClass(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::RegisteredProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_RegisteredProviderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::RegisteredProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->get_RegisteredProviderName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork<D>::ShowConnectionUI() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork)->ShowConnectionUI());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork2<D>::GetVoiceCallSupportAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2)->GetVoiceCallSupportAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork2<D>::RegistrationUiccApps() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2)->get_RegistrationUiccApps(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo> consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetwork3<D>::GetCellsInfoAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3)->GetCellsInfoAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChange<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandNetwork consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChange<D>::Network() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandNetwork value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange)->get_Network(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange> consume_Windows_Networking_NetworkOperators_IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails<D>::NetworkRegistrationStateChanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails)->get_NetworkRegistrationStateChanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandPco<D>::Data() const
{
    Windows::Storage::Streams::IBuffer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPco)->get_Data(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandPco<D>::IsComplete() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPco)->get_IsComplete(&result));
    return result;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandPco<D>::DeviceId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPco)->get_DeviceId(put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPco consume_Windows_Networking_NetworkOperators_IMobileBroadbandPcoDataChangeTriggerDetails<D>::UpdatedData() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPco result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails)->get_UpdatedData(put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinType consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::Type() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinLockState consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::LockState() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinLockState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_LockState(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinFormat consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::Format() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinFormat value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_Format(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_Enabled(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::MaxLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_MaxLength(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::MinLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_MinLength(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::AttemptsRemaining() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->get_AttemptsRemaining(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::EnableAsync(param::hstring const& currentPin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->EnableAsync(get_abi(currentPin), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::DisableAsync(param::hstring const& currentPin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->DisableAsync(get_abi(currentPin), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::EnterAsync(param::hstring const& currentPin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->EnterAsync(get_abi(currentPin), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::ChangeAsync(param::hstring const& currentPin, param::hstring const& newPin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->ChangeAsync(get_abi(currentPin), get_abi(newPin), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPin<D>::UnblockAsync(param::hstring const& pinUnblockKey, param::hstring const& newPin) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPin)->UnblockAsync(get_abi(pinUnblockKey), get_abi(newPin), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChange<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinType consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChange<D>::PinType() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange)->get_PinType(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPinLockState consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChange<D>::PinLockState() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPinLockState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange)->get_PinLockState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinLockStateChangeTriggerDetails<D>::PinLockStateChanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails)->get_PinLockStateChanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinType> consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinManager<D>::SupportedPins() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinManager)->get_SupportedPins(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandPin consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinManager<D>::GetPin(Windows::Networking::NetworkOperators::MobileBroadbandPinType const& pinType) const
{
    Windows::Networking::NetworkOperators::MobileBroadbandPin value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinManager)->GetPin(get_abi(pinType), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinOperationResult<D>::IsSuccessful() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult)->get_IsSuccessful(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandPinOperationResult<D>::AttemptsRemaining() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult)->get_AttemptsRemaining(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChange<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandRadioState consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChange<D>::RadioState() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandRadioState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange)->get_RadioState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange> consume_Windows_Networking_NetworkOperators_IMobileBroadbandRadioStateChangeTriggerDetails<D>::RadioStateChanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails)->get_RadioStateChanges(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::IsBackoffEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->get_IsBackoffEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::IsWiFiHardwareIntegrated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->get_IsWiFiHardwareIntegrated(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::IsSarControlledByHardware() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->get_IsSarControlledByHardware(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::Antennas() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->get_Antennas(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::HysteresisTimerPeriod() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->get_HysteresisTimerPeriod(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::TransmissionStateChanged(Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->add_TransmissionStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::TransmissionStateChanged_revoker consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::TransmissionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TransmissionStateChanged_revoker>(this, TransmissionStateChanged(handler));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::TransmissionStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->remove_TransmissionStateChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::EnableBackoffAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->EnableBackoffAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::DisableBackoffAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->DisableBackoffAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::SetConfigurationAsync(param::async_iterable<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> const& antennas) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->SetConfigurationAsync(get_abi(antennas), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::RevertSarToHardwareControlAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->RevertSarToHardwareControlAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::SetTransmissionStateChangedHysteresisAsync(Windows::Foundation::TimeSpan const& timerPeriod) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->SetTransmissionStateChangedHysteresisAsync(get_abi(timerPeriod), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::GetIsTransmittingAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->GetIsTransmittingAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::StartTransmissionStateMonitoring() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->StartTransmissionStateMonitoring());
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IMobileBroadbandSarManager<D>::StopTransmissionStateMonitoring() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandSarManager)->StopTransmissionStateMonitoring());
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IMobileBroadbandTransmissionStateChangedEventArgs<D>::IsTransmitting() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs)->get_IsTransmitting(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IMobileBroadbandUicc<D>::SimIccId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUicc)->get_SimIccId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandUicc<D>::GetUiccAppsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUicc)->GetUiccAppsAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp<D>::Id() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::UiccAppKind consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp<D>::Kind() const
{
    Windows::Networking::NetworkOperators::UiccAppKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp<D>::GetRecordDetailsAsync(param::async_iterable<uint32_t> const& uiccFilePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp)->GetRecordDetailsAsync(get_abi(uiccFilePath), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult> consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccApp<D>::ReadRecordAsync(param::async_iterable<uint32_t> const& uiccFilePath, int32_t recordIndex) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp)->ReadRecordAsync(get_abi(uiccFilePath), recordIndex, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppReadRecordResult<D>::Status() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppReadRecordResult<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::Status() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::UiccAppRecordKind consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::Kind() const
{
    Windows::Networking::NetworkOperators::UiccAppRecordKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::RecordCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_RecordCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::RecordSize() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_RecordSize(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::UiccAccessCondition consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::ReadAccessCondition() const
{
    Windows::Networking::NetworkOperators::UiccAccessCondition value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_ReadAccessCondition(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::UiccAccessCondition consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppRecordDetailsResult<D>::WriteAccessCondition() const
{
    Windows::Networking::NetworkOperators::UiccAccessCondition value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult)->get_WriteAccessCondition(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppsResult<D>::Status() const
{
    Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> consume_Windows_Networking_NetworkOperators_IMobileBroadbandUiccAppsResult<D>::UiccApps() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult)->get_UiccApps(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind consume_Windows_Networking_NetworkOperators_INetworkOperatorDataUsageTriggerDetails<D>::NotificationKind() const
{
    Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails)->get_NotificationKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::NotificationType() const
{
    Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_NotificationType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::EncodingType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_EncodingType(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_Message(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::RuleId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_RuleId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sms::ISmsMessage consume_Windows_Networking_NetworkOperators_INetworkOperatorNotificationEventDetails<D>::SmsMessage() const
{
    Windows::Devices::Sms::ISmsMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails)->get_SmsMessage(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration<D>::Ssid() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration)->get_Ssid(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration<D>::Ssid(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration)->put_Ssid(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration<D>::Passphrase() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration)->get_Passphrase(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringAccessPointConfiguration<D>::Passphrase(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration)->put_Passphrase(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClient<D>::MacAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient)->get_MacAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClient<D>::HostNames() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient)->get_HostNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient> consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringClientManager<D>::GetTetheringClients() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager)->GetTetheringClients(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringEntitlementCheck<D>::AuthorizeTethering(bool allow, param::hstring const& entitlementFailureReason) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck)->AuthorizeTethering(allow, get_abi(entitlementFailureReason)));
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::MaxClientCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->get_MaxClientCount(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::ClientCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->get_ClientCount(&value));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::TetheringOperationalState consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::TetheringOperationalState() const
{
    Windows::Networking::NetworkOperators::TetheringOperationalState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->get_TetheringOperationalState(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::GetCurrentAccessPointConfiguration() const
{
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration configuration{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->GetCurrentAccessPointConfiguration(put_abi(configuration)));
    return configuration;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::ConfigureAccessPointAsync(Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration const& configuration) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->ConfigureAccessPointAsync(get_abi(configuration), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::StartTetheringAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->StartTetheringAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManager<D>::StopTetheringAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager)->StopTetheringAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Networking::NetworkOperators::TetheringCapability consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics<D>::GetTetheringCapability(param::hstring const& networkAccountId) const
{
    Windows::Networking::NetworkOperators::TetheringCapability value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics)->GetTetheringCapability(get_abi(networkAccountId), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics<D>::CreateFromNetworkAccountId(param::hstring const& networkAccountId) const
{
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager ppManager{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics)->CreateFromNetworkAccountId(get_abi(networkAccountId), put_abi(ppManager)));
    return ppManager;
}

template <typename D> Windows::Networking::NetworkOperators::TetheringCapability consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics2<D>::GetTetheringCapabilityFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile) const
{
    Windows::Networking::NetworkOperators::TetheringCapability result{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2)->GetTetheringCapabilityFromConnectionProfile(get_abi(profile), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics2<D>::CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile) const
{
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager ppManager{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2)->CreateFromConnectionProfile(get_abi(profile), put_abi(ppManager)));
    return ppManager;
}

template <typename D> Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringManagerStatics3<D>::CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager ppManager{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3)->CreateFromConnectionProfileWithTargetAdapter(get_abi(profile), get_abi(adapter), put_abi(ppManager)));
    return ppManager;
}

template <typename D> Windows::Networking::NetworkOperators::TetheringOperationStatus consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringOperationResult<D>::Status() const
{
    Windows::Networking::NetworkOperators::TetheringOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_INetworkOperatorTetheringOperationResult<D>::AdditionalErrorMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult)->get_AdditionalErrorMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_NetworkOperators_IProvisionFromXmlDocumentResults<D>::AllElementsProvisioned() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults)->get_AllElementsProvisioned(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IProvisionFromXmlDocumentResults<D>::ProvisionResultsXml() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults)->get_ProvisionResultsXml(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IProvisionedProfile<D>::UpdateCost(Windows::Networking::Connectivity::NetworkCostType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisionedProfile)->UpdateCost(get_abi(value)));
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IProvisionedProfile<D>::UpdateUsage(Windows::Networking::NetworkOperators::ProfileUsage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisionedProfile)->UpdateUsage(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults> consume_Windows_Networking_NetworkOperators_IProvisioningAgent<D>::ProvisionFromXmlDocumentAsync(param::hstring const& provisioningXmlDocument) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisioningAgent)->ProvisionFromXmlDocumentAsync(get_abi(provisioningXmlDocument), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Networking::NetworkOperators::ProvisionedProfile consume_Windows_Networking_NetworkOperators_IProvisioningAgent<D>::GetProvisionedProfile(Windows::Networking::NetworkOperators::ProfileMediaType const& mediaType, param::hstring const& profileName) const
{
    Windows::Networking::NetworkOperators::ProvisionedProfile provisionedProfile{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisioningAgent)->GetProvisionedProfile(get_abi(mediaType), get_abi(profileName), put_abi(provisionedProfile)));
    return provisionedProfile;
}

template <typename D> Windows::Networking::NetworkOperators::ProvisioningAgent consume_Windows_Networking_NetworkOperators_IProvisioningAgentStaticMethods<D>::CreateFromNetworkAccountId(param::hstring const& networkAccountId) const
{
    Windows::Networking::NetworkOperators::ProvisioningAgent provisioningAgent{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods)->CreateFromNetworkAccountId(get_abi(networkAccountId), put_abi(provisioningAgent)));
    return provisioningAgent;
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_ITetheringEntitlementCheckTriggerDetails<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_ITetheringEntitlementCheckTriggerDetails<D>::AllowTethering() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails)->AllowTethering());
}

template <typename D> void consume_Windows_Networking_NetworkOperators_ITetheringEntitlementCheckTriggerDetails<D>::DenyTethering(param::hstring const& entitlementFailureReason) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails)->DenyTethering(get_abi(entitlementFailureReason)));
}

template <typename D> uint8_t consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::DataCodingScheme() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->get_DataCodingScheme(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::DataCodingScheme(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->put_DataCodingScheme(value));
}

template <typename D> com_array<uint8_t> consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::GetPayload() const
{
    com_array<uint8_t> value;
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->GetPayload(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::SetPayload(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->SetPayload(value.size(), get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::PayloadAsText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->get_PayloadAsText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IUssdMessage<D>::PayloadAsText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessage)->put_PayloadAsText(get_abi(value)));
}

template <typename D> Windows::Networking::NetworkOperators::UssdMessage consume_Windows_Networking_NetworkOperators_IUssdMessageFactory<D>::CreateMessage(param::hstring const& messageText) const
{
    Windows::Networking::NetworkOperators::UssdMessage ussdMessage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdMessageFactory)->CreateMessage(get_abi(messageText), put_abi(ussdMessage)));
    return ussdMessage;
}

template <typename D> Windows::Networking::NetworkOperators::UssdResultCode consume_Windows_Networking_NetworkOperators_IUssdReply<D>::ResultCode() const
{
    Windows::Networking::NetworkOperators::UssdResultCode value{};
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdReply)->get_ResultCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::NetworkOperators::UssdMessage consume_Windows_Networking_NetworkOperators_IUssdReply<D>::Message() const
{
    Windows::Networking::NetworkOperators::UssdMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdReply)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::UssdReply> consume_Windows_Networking_NetworkOperators_IUssdSession<D>::SendMessageAndGetReplyAsync(Windows::Networking::NetworkOperators::UssdMessage const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::UssdReply> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdSession)->SendMessageAndGetReplyAsync(get_abi(message), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Networking_NetworkOperators_IUssdSession<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdSession)->Close());
}

template <typename D> Windows::Networking::NetworkOperators::UssdSession consume_Windows_Networking_NetworkOperators_IUssdSessionStatics<D>::CreateFromNetworkAccountId(param::hstring const& networkAccountId) const
{
    Windows::Networking::NetworkOperators::UssdSession ussdSession{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdSessionStatics)->CreateFromNetworkAccountId(get_abi(networkAccountId), put_abi(ussdSession)));
    return ussdSession;
}

template <typename D> Windows::Networking::NetworkOperators::UssdSession consume_Windows_Networking_NetworkOperators_IUssdSessionStatics<D>::CreateFromNetworkInterfaceId(param::hstring const& networkInterfaceId) const
{
    Windows::Networking::NetworkOperators::UssdSession ussdSession{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::NetworkOperators::IUssdSessionStatics)->CreateFromNetworkInterfaceId(get_abi(networkInterfaceId), put_abi(ussdSession)));
    return ussdSession;
}

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESim> : produce_base<D, Windows::Networking::NetworkOperators::IESim>
{
    int32_t WINRT_CALL get_AvailableMemoryInBytes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableMemoryInBytes, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().AvailableMemoryInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Eid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Eid, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Eid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirmwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirmwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FirmwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MobileBroadbandModemDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MobileBroadbandModemDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MobileBroadbandModemDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Policy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Policy, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimPolicy));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimPolicy>(this->shim().Policy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimState));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProfiles(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimProfile>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimProfile>>(this->shim().GetProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteProfileAsync(void* profileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteProfileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().DeleteProfileAsync(*reinterpret_cast<hstring const*>(&profileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadProfileMetadataAsync(void* activationCode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProfileMetadataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult>>(this->shim().DownloadProfileMetadataAsync(*reinterpret_cast<hstring const*>(&activationCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().ResetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ProfileChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProfileChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESim, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProfileChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProfileChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProfileChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESim2> : produce_base<D, Windows::Networking::NetworkOperators::IESim2>
{
    int32_t WINRT_CALL Discover(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Discover, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimDiscoverResult));
            *result = detach_from<Windows::Networking::NetworkOperators::ESimDiscoverResult>(this->shim().Discover());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscoverWithServerAddressAndMatchingId(void* serverAddress, void* matchingId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Discover, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimDiscoverResult), hstring const&, hstring const&);
            *result = detach_from<Windows::Networking::NetworkOperators::ESimDiscoverResult>(this->shim().Discover(*reinterpret_cast<hstring const*>(&serverAddress), *reinterpret_cast<hstring const*>(&matchingId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscoverAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscoverAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult>>(this->shim().DiscoverAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DiscoverWithServerAddressAndMatchingIdAsync(void* serverAddress, void* matchingId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiscoverAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimDiscoverResult>>(this->shim().DiscoverAsync(*reinterpret_cast<hstring const*>(&serverAddress), *reinterpret_cast<hstring const*>(&matchingId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimAddedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IESimAddedEventArgs>
{
    int32_t WINRT_CALL get_ESim(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ESim, WINRT_WRAP(Windows::Networking::NetworkOperators::ESim));
            *value = detach_from<Windows::Networking::NetworkOperators::ESim>(this->shim().ESim());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimDiscoverEvent> : produce_base<D, Windows::Networking::NetworkOperators::IESimDiscoverEvent>
{
    int32_t WINRT_CALL get_MatchingId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MatchingId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MatchingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RspServerAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RspServerAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RspServerAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimDiscoverResult> : produce_base<D, Windows::Networking::NetworkOperators::IESimDiscoverResult>
{
    int32_t WINRT_CALL get_Events(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Events, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimDiscoverEvent>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::ESimDiscoverEvent>>(this->shim().Events());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::ESimDiscoverResultKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimDiscoverResultKind));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimDiscoverResultKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProfileMetadata(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileMetadata, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfileMetadata));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfileMetadata>(this->shim().ProfileMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimOperationResult));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimOperationResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult> : produce_base<D, Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult>
{
    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimOperationResult));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimOperationResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProfileMetadata(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileMetadata, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfileMetadata));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfileMetadata>(this->shim().ProfileMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimManagerStatics> : produce_base<D, Windows::Networking::NetworkOperators::IESimManagerStatics>
{
    int32_t WINRT_CALL get_ServiceInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceInfo, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimServiceInfo));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimServiceInfo>(this->shim().ServiceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateESimWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateESimWatcher, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimWatcher));
            *result = detach_from<Windows::Networking::NetworkOperators::ESimWatcher>(this->shim().TryCreateESimWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ServiceInfoChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceInfoChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ServiceInfoChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServiceInfoChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServiceInfoChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServiceInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimOperationResult> : produce_base<D, Windows::Networking::NetworkOperators::IESimOperationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::ESimOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimOperationStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimPolicy> : produce_base<D, Windows::Networking::NetworkOperators::IESimPolicy>
{
    int32_t WINRT_CALL get_ShouldEnableManagingUi(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldEnableManagingUi, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldEnableManagingUi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimProfile> : produce_base<D, Windows::Networking::NetworkOperators::IESimProfile>
{
    int32_t WINRT_CALL get_Class(Windows::Networking::NetworkOperators::ESimProfileClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Class, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfileClass));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfileClass>(this->shim().Class());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nickname(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nickname, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Nickname());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Policy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Policy, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfilePolicy));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfilePolicy>(this->shim().Policy());
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

    int32_t WINRT_CALL get_ProviderIcon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderIcon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().ProviderIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimProfileState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfileState));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfileState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().DisableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().EnableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNicknameAsync(void* newNickname, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNicknameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().SetNicknameAsync(*reinterpret_cast<hstring const*>(&newNickname)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimProfileMetadata> : produce_base<D, Windows::Networking::NetworkOperators::IESimProfileMetadata>
{
    int32_t WINRT_CALL get_IsConfirmationCodeRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConfirmationCodeRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConfirmationCodeRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Policy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Policy, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfilePolicy));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfilePolicy>(this->shim().Policy());
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

    int32_t WINRT_CALL get_ProviderIcon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderIcon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().ProviderIcon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Networking::NetworkOperators::ESimProfileMetadataState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimProfileMetadataState));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimProfileMetadataState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DenyInstallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DenyInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().DenyInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfirmInstallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfirmInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress>>(this->shim().ConfirmInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfirmInstallWithConfirmationCodeAsync(void* confirmationCode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfirmInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Networking::NetworkOperators::ESimOperationResult, Windows::Networking::NetworkOperators::ESimProfileInstallProgress>>(this->shim().ConfirmInstallAsync(*reinterpret_cast<hstring const*>(&confirmationCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PostponeInstallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostponeInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ESimOperationResult>>(this->shim().PostponeInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimProfileMetadata, Windows::Foundation::IInspectable> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimProfilePolicy> : produce_base<D, Windows::Networking::NetworkOperators::IESimProfilePolicy>
{
    int32_t WINRT_CALL get_CanDelete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDelete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDelete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDisable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDisable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDisable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsManagedByEnterprise(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsManagedByEnterprise, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsManagedByEnterprise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimRemovedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IESimRemovedEventArgs>
{
    int32_t WINRT_CALL get_ESim(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ESim, WINRT_WRAP(Windows::Networking::NetworkOperators::ESim));
            *value = detach_from<Windows::Networking::NetworkOperators::ESim>(this->shim().ESim());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimServiceInfo> : produce_base<D, Windows::Networking::NetworkOperators::IESimServiceInfo>
{
    int32_t WINRT_CALL get_AuthenticationPreference(Windows::Networking::NetworkOperators::ESimAuthenticationPreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationPreference, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimAuthenticationPreference));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimAuthenticationPreference>(this->shim().AuthenticationPreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsESimUiEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsESimUiEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsESimUiEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimUpdatedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IESimUpdatedEventArgs>
{
    int32_t WINRT_CALL get_ESim(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ESim, WINRT_WRAP(Windows::Networking::NetworkOperators::ESim));
            *value = detach_from<Windows::Networking::NetworkOperators::ESim>(this->shim().ESim());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IESimWatcher> : produce_base<D, Windows::Networking::NetworkOperators::IESimWatcher>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::ESimWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::ESimWatcherStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::ESimWatcherStatus>(this->shim().Status());
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

    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimAddedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimRemovedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::ESimWatcher, Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IFdnAccessManagerStatics> : produce_base<D, Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>
{
    int32_t WINRT_CALL RequestUnlockAsync(void* contactListId, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUnlockAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *returnValue = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestUnlockAsync(*reinterpret_cast<hstring const*>(&contactListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContext> : produce_base<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContext>
{
    int32_t WINRT_CALL get_WirelessNetworkId(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WirelessNetworkId, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().WirelessNetworkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAdapter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAdapter, WINRT_WRAP(Windows::Networking::Connectivity::NetworkAdapter));
            *value = detach_from<Windows::Networking::Connectivity::NetworkAdapter>(this->shim().NetworkAdapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedirectMessageUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedirectMessageUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().RedirectMessageUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedirectMessageXml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedirectMessageXml, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().RedirectMessageXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().AuthenticationUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IssueCredentials(void* userName, void* password, void* extraParameters, bool markAsManualConnectOnFailure) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssueCredentials, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&, bool);
            this->shim().IssueCredentials(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<hstring const*>(&password), *reinterpret_cast<hstring const*>(&extraParameters), markAsManualConnectOnFailure);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AbortAuthentication(bool markAsManual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbortAuthentication, WINRT_WRAP(void), bool);
            this->shim().AbortAuthentication(markAsManual);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SkipAuthentication() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkipAuthentication, WINRT_WRAP(void));
            this->shim().SkipAuthentication();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TriggerAttentionRequired(void* packageRelativeApplicationId, void* applicationParameters) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerAttentionRequired, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().TriggerAttentionRequired(*reinterpret_cast<hstring const*>(&packageRelativeApplicationId), *reinterpret_cast<hstring const*>(&applicationParameters));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2> : produce_base<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2>
{
    int32_t WINRT_CALL IssueCredentialsAsync(void* userName, void* password, void* extraParameters, bool markAsManualConnectOnFailure, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IssueCredentialsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult>), hstring const, hstring const, hstring const, bool);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult>>(this->shim().IssueCredentialsAsync(*reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<hstring const*>(&password), *reinterpret_cast<hstring const*>(&extraParameters), markAsManualConnectOnFailure));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics> : produce_base<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>
{
    int32_t WINRT_CALL TryGetAuthenticationContext(void* evenToken, void** context, bool* isValid) noexcept final
    {
        try
        {
            *context = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAuthenticationContext, WINRT_WRAP(bool), hstring const&, Windows::Networking::NetworkOperators::HotspotAuthenticationContext&);
            *isValid = detach_from<bool>(this->shim().TryGetAuthenticationContext(*reinterpret_cast<hstring const*>(&evenToken), *reinterpret_cast<Windows::Networking::NetworkOperators::HotspotAuthenticationContext*>(context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails> : produce_base<D, Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails>
{
    int32_t WINRT_CALL get_EventToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EventToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult> : produce_base<D, Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult>
{
    int32_t WINRT_CALL get_HasNetworkErrorOccurred(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNetworkErrorOccurred, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNetworkErrorOccurred());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseCode(Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCode, WINRT_WRAP(Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode));
            *value = detach_from<Windows::Networking::NetworkOperators::HotspotAuthenticationResponseCode>(this->shim().ResponseCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LogoffUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LogoffUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LogoffUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationReplyXml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationReplyXml, WINRT_WRAP(Windows::Data::Xml::Dom::XmlDocument));
            *value = detach_from<Windows::Data::Xml::Dom::XmlDocument>(this->shim().AuthenticationReplyXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics> : produce_base<D, Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>
{
    int32_t WINRT_CALL get_EFSpn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFSpn, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFSpn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid1, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid2, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics> : produce_base<D, Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>
{
    int32_t WINRT_CALL get_EFSpn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFSpn, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFSpn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid1, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid2, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics> : produce_base<D, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>
{
    int32_t WINRT_CALL get_EFOns(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFOns, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFOns());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EFSpn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFSpn, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFSpn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid1, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid2, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics> : produce_base<D, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>
{
    int32_t WINRT_CALL get_EFSpn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFSpn, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFSpn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EFOpl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFOpl, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFOpl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EFPnn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EFPnn, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().EFPnn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid1, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gid2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gid2, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Gid2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount>
{
    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceProviderGuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProviderGuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ServiceProviderGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentNetwork(void** network) noexcept final
    {
        try
        {
            *network = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentNetwork, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandNetwork));
            *network = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>(this->shim().CurrentNetwork());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentDeviceInformation(void** deviceInformation) noexcept final
    {
        try
        {
            *deviceInformation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentDeviceInformation, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation));
            *deviceInformation = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation>(this->shim().CurrentDeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount2> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount2>
{
    int32_t WINRT_CALL GetConnectionProfiles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectionProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>>(this->shim().GetConnectionProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount3> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccount3>
{
    int32_t WINRT_CALL get_AccountExperienceUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountExperienceUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().AccountExperienceUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs>
{
    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>
{
    int32_t WINRT_CALL get_AvailableNetworkAccountIds(void** ppAccountIds) noexcept final
    {
        try
        {
            *ppAccountIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableNetworkAccountIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *ppAccountIds = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AvailableNetworkAccountIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ppAccount) noexcept final
    {
        try
        {
            *ppAccount = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNetworkAccountId, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandAccount), hstring const&);
            *ppAccount = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandAccount>(this->shim().CreateFromNetworkAccountId(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs>
{
    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasDeviceInformationChanged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasDeviceInformationChanged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasDeviceInformationChanged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNetworkChanged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNetworkChanged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNetworkChanged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher>
{
    int32_t WINRT_CALL add_AccountAdded(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AccountAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccountAdded(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccountAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccountAdded(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_AccountUpdated(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AccountUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccountUpdated(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccountUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccountUpdated(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_AccountRemoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AccountRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccountRemoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccountRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccountRemoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus));
            *status = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcherStatus>(this->shim().Status());
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
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar>
{
    int32_t WINRT_CALL get_AntennaIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AntennaIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AntennaIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SarBackoffIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SarBackoffIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SarBackoffIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>
{
    int32_t WINRT_CALL CreateWithIndex(int32_t antennaIndex, int32_t sarBackoffIndex, void** antennaSar) noexcept final
    {
        try
        {
            *antennaSar = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithIndex, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar), int32_t, int32_t);
            *antennaSar = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>(this->shim().CreateWithIndex(antennaIndex, sarBackoffIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma>
{
    int32_t WINRT_CALL get_BaseStationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().BaseStationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseStationPNCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationPNCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().BaseStationPNCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseStationLatitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationLatitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().BaseStationLatitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseStationLongitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationLongitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().BaseStationLongitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseStationLastBroadcastGpsTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationLastBroadcastGpsTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().BaseStationLastBroadcastGpsTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().NetworkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PilotSignalStrengthInDB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PilotSignalStrengthInDB, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().PilotSignalStrengthInDB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().SystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm>
{
    int32_t WINRT_CALL get_BaseStationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseStationId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().BaseStationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CellId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelNumber, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().ChannelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationAreaCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().LocationAreaCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceivedSignalStrengthInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivedSignalStrengthInDBm, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ReceivedSignalStrengthInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimingAdvanceInBitPeriods, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().TimingAdvanceInBitPeriods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellLte> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellLte>
{
    int32_t WINRT_CALL get_CellId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CellId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelNumber, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().ChannelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalCellId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalCellId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PhysicalCellId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReferenceSignalReceivedPowerInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReferenceSignalReceivedPowerInDBm, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ReferenceSignalReceivedPowerInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReferenceSignalReceivedQualityInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReferenceSignalReceivedQualityInDBm, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ReferenceSignalReceivedQualityInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimingAdvanceInBitPeriods, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().TimingAdvanceInBitPeriods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackingAreaCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackingAreaCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().TrackingAreaCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma>
{
    int32_t WINRT_CALL get_CellId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CellId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellParameterId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellParameterId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CellParameterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelNumber, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().ChannelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationAreaCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().LocationAreaCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PathLossInDB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PathLossInDB, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().PathLossInDB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceivedSignalCodePowerInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivedSignalCodePowerInDBm, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ReceivedSignalCodePowerInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimingAdvanceInBitPeriods(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimingAdvanceInBitPeriods, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().TimingAdvanceInBitPeriods());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts>
{
    int32_t WINRT_CALL get_CellId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().CellId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelNumber, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().ChannelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationAreaCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationAreaCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().LocationAreaCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PathLossInDB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PathLossInDB, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().PathLossInDB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrimaryScramblingCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryScramblingCode, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PrimaryScramblingCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceivedSignalCodePowerInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivedSignalCodePowerInDBm, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ReceivedSignalCodePowerInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalToNoiseRatioInDB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalToNoiseRatioInDB, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().SignalToNoiseRatioInDB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo>
{
    int32_t WINRT_CALL get_NeighboringCellsCdma(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringCellsCdma, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>>(this->shim().NeighboringCellsCdma());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeighboringCellsGsm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringCellsGsm, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>>(this->shim().NeighboringCellsGsm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeighboringCellsLte(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringCellsLte, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>>(this->shim().NeighboringCellsLte());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeighboringCellsTdscdma(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringCellsTdscdma, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>>(this->shim().NeighboringCellsTdscdma());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeighboringCellsUmts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringCellsUmts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>>(this->shim().NeighboringCellsUmts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServingCellsCdma(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServingCellsCdma, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellCdma>>(this->shim().ServingCellsCdma());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServingCellsGsm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServingCellsGsm, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellGsm>>(this->shim().ServingCellsGsm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServingCellsLte(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServingCellsLte, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellLte>>(this->shim().ServingCellsLte());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServingCellsTdscdma(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServingCellsTdscdma, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma>>(this->shim().ServingCellsTdscdma());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServingCellsUmts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServingCellsUmts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandCellUmts>>(this->shim().ServingCellsUmts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation>
{
    int32_t WINRT_CALL get_NetworkDeviceStatus(Windows::Networking::NetworkOperators::NetworkDeviceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkDeviceStatus, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkDeviceStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::NetworkDeviceStatus>(this->shim().NetworkDeviceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Manufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Manufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Manufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Model(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Model, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Model());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirmwareInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirmwareInformation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FirmwareInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularClass(Windows::Devices::Sms::CellularClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularClass, WINRT_WRAP(Windows::Devices::Sms::CellularClass));
            *value = detach_from<Windows::Devices::Sms::CellularClass>(this->shim().CellularClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataClasses(Windows::Networking::NetworkOperators::DataClasses* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataClasses, WINRT_WRAP(Windows::Networking::NetworkOperators::DataClasses));
            *value = detach_from<Windows::Networking::NetworkOperators::DataClasses>(this->shim().DataClasses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomDataClass(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomDataClass, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CustomDataClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MobileEquipmentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MobileEquipmentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MobileEquipmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TelephoneNumbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TelephoneNumbers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().TelephoneNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubscriberId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscriberId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubscriberId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimIccId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimIccId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimIccId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceType(Windows::Networking::NetworkOperators::MobileBroadbandDeviceType* pDeviceType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceType, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceType));
            *pDeviceType = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceType>(this->shim().DeviceType());
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

    int32_t WINRT_CALL get_CurrentRadioState(Windows::Networking::NetworkOperators::MobileBroadbandRadioState* pCurrentState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentRadioState, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandRadioState));
            *pCurrentState = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandRadioState>(this->shim().CurrentRadioState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2>
{
    int32_t WINRT_CALL get_PinManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinManager, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinManager));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinManager>(this->shim().PinManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Revision(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revision, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SerialNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SerialNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3>
{
    int32_t WINRT_CALL get_SimSpn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimSpn, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimSpn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimPnn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimPnn, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimPnn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimGid1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimGid1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimGid1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService>
{
    int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DeviceServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedCommands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedCommands, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().SupportedCommands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenDataSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenDataSession, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession>(this->shim().OpenDataSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenCommandSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenCommandSession, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession>(this->shim().OpenCommandSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult>
{
    int32_t WINRT_CALL get_StatusCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().StatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ResponseData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession>
{
    int32_t WINRT_CALL SendQueryCommandAsync(uint32_t commandId, void* data, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendQueryCommandAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>), uint32_t, Windows::Storage::Streams::IBuffer const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>>(this->shim().SendQueryCommandAsync(commandId, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendSetCommandAsync(uint32_t commandId, void* data, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendSetCommandAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>), uint32_t, Windows::Storage::Streams::IBuffer const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult>>(this->shim().SendSetCommandAsync(commandId, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CloseSession() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseSession, WINRT_WRAP(void));
            this->shim().CloseSession();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_ReceivedData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivedData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ReceivedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession>
{
    int32_t WINRT_CALL WriteDataAsync(void* value, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IBuffer const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteDataAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CloseSession() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseSession, WINRT_WRAP(void));
            this->shim().CloseSession();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataReceived(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().DataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession, Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataReceived(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataReceived(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation>
{
    int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DeviceServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDataReadSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataReadSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDataReadSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDataWriteSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataWriteSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDataWriteSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails>
{
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

    int32_t WINRT_CALL get_DeviceServiceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServiceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DeviceServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReceivedData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivedData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ReceivedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem>
{
    int32_t WINRT_CALL get_CurrentAccount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentAccount, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandAccount));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandAccount>(this->shim().CurrentAccount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxDeviceServiceCommandSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxDeviceServiceCommandSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxDeviceServiceCommandSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxDeviceServiceDataSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxDeviceServiceDataSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxDeviceServiceDataSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation>>(this->shim().DeviceServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceService(winrt::guid deviceServiceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceService, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandDeviceService), winrt::guid const&);
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandDeviceService>(this->shim().GetDeviceService(*reinterpret_cast<winrt::guid const*>(&deviceServiceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsResetSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResetSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsResetSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentConfigurationAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration>>(this->shim().GetCurrentConfigurationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentNetwork(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentNetwork, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandNetwork));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>(this->shim().CurrentNetwork());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem2> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem2>
{
    int32_t WINRT_CALL GetIsPassthroughEnabledAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsPassthroughEnabledAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsPassthroughEnabledAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsPassthroughEnabledAsync(bool value, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsPassthroughEnabledAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus>), bool);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandModemStatus>>(this->shim().SetIsPassthroughEnabledAsync(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem3> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModem3>
{
    int32_t WINRT_CALL TryGetPcoAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPcoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPco>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPco>>(this->shim().TryGetPcoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInEmergencyCallMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInEmergencyCallMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInEmergencyCallMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsInEmergencyCallModeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInEmergencyCallModeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsInEmergencyCallModeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandModem, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsInEmergencyCallModeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsInEmergencyCallModeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsInEmergencyCallModeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration>
{
    int32_t WINRT_CALL get_Uicc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uicc, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandUicc));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandUicc>(this->shim().Uicc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HomeProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HomeProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HomeProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HomeProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2>
{
    int32_t WINRT_CALL get_SarManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SarManager, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandSarManager));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandSarManager>(this->shim().SarManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation>
{
    int32_t WINRT_CALL AddAllowedHost(void* host) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAllowedHost, WINRT_WRAP(void), Windows::Networking::HostName const&);
            this->shim().AddAllowedHost(*reinterpret_cast<Windows::Networking::HostName const*>(&host));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddAllowedHostRange(void* first, void* last) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAllowedHostRange, WINRT_WRAP(void), Windows::Networking::HostName const&, Windows::Networking::HostName const&);
            this->shim().AddAllowedHostRange(*reinterpret_cast<Windows::Networking::HostName const*>(&first), *reinterpret_cast<Windows::Networking::HostName const*>(&last));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyConfigurationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ApplyConfigurationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearConfigurationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearConfigurationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>
{
    int32_t WINRT_CALL Create(void* modemDeviceId, void* ruleGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation), hstring const&, hstring const&);
            *result = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation>(this->shim().Create(*reinterpret_cast<hstring const*>(&modemDeviceId), *reinterpret_cast<hstring const*>(&ruleGroupId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromId(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandModem), hstring const&);
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandModem>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandModem));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandModem>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork>
{
    int32_t WINRT_CALL get_NetworkAdapter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAdapter, WINRT_WRAP(Windows::Networking::Connectivity::NetworkAdapter));
            *value = detach_from<Windows::Networking::Connectivity::NetworkAdapter>(this->shim().NetworkAdapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkRegistrationState(Windows::Networking::NetworkOperators::NetworkRegistrationState* registrationState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkRegistrationState, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkRegistrationState));
            *registrationState = detach_from<Windows::Networking::NetworkOperators::NetworkRegistrationState>(this->shim().NetworkRegistrationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegistrationNetworkError(uint32_t* networkError) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegistrationNetworkError, WINRT_WRAP(uint32_t));
            *networkError = detach_from<uint32_t>(this->shim().RegistrationNetworkError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PacketAttachNetworkError(uint32_t* networkError) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PacketAttachNetworkError, WINRT_WRAP(uint32_t));
            *networkError = detach_from<uint32_t>(this->shim().PacketAttachNetworkError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivationNetworkError(uint32_t* networkError) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationNetworkError, WINRT_WRAP(uint32_t));
            *networkError = detach_from<uint32_t>(this->shim().ActivationNetworkError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessPointName(void** apn) noexcept final
    {
        try
        {
            *apn = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessPointName, WINRT_WRAP(hstring));
            *apn = detach_from<hstring>(this->shim().AccessPointName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegisteredDataClass(Windows::Networking::NetworkOperators::DataClasses* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisteredDataClass, WINRT_WRAP(Windows::Networking::NetworkOperators::DataClasses));
            *value = detach_from<Windows::Networking::NetworkOperators::DataClasses>(this->shim().RegisteredDataClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegisteredProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisteredProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RegisteredProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegisteredProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisteredProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RegisteredProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowConnectionUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowConnectionUI, WINRT_WRAP(void));
            this->shim().ShowConnectionUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2>
{
    int32_t WINRT_CALL GetVoiceCallSupportAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVoiceCallSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetVoiceCallSupportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegistrationUiccApps(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegistrationUiccApps, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>>(this->shim().RegistrationUiccApps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3>
{
    int32_t WINRT_CALL GetCellsInfoAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCellsInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo>>(this->shim().GetCellsInfoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange>
{
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

    int32_t WINRT_CALL get_Network(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Network, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandNetwork));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandNetwork>(this->shim().Network());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails>
{
    int32_t WINRT_CALL get_NetworkRegistrationStateChanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkRegistrationStateChanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange>>(this->shim().NetworkRegistrationStateChanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPco> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPco>
{
    int32_t WINRT_CALL get_Data(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *result = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComplete(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComplete, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails>
{
    int32_t WINRT_CALL get_UpdatedData(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdatedData, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPco));
            *result = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPco>(this->shim().UpdatedData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPin> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPin>
{
    int32_t WINRT_CALL get_Type(Windows::Networking::NetworkOperators::MobileBroadbandPinType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinType));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LockState(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockState, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinLockState>(this->shim().LockState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Format(Windows::Networking::NetworkOperators::MobileBroadbandPinFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinFormat));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttemptsRemaining(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttemptsRemaining, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AttemptsRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableAsync(void* currentPin, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>>(this->shim().EnableAsync(*reinterpret_cast<hstring const*>(&currentPin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableAsync(void* currentPin, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>>(this->shim().DisableAsync(*reinterpret_cast<hstring const*>(&currentPin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnterAsync(void* currentPin, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>>(this->shim().EnterAsync(*reinterpret_cast<hstring const*>(&currentPin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeAsync(void* currentPin, void* newPin, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>), hstring const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>>(this->shim().ChangeAsync(*reinterpret_cast<hstring const*>(&currentPin), *reinterpret_cast<hstring const*>(&newPin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnblockAsync(void* pinUnblockKey, void* newPin, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnblockAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>), hstring const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult>>(this->shim().UnblockAsync(*reinterpret_cast<hstring const*>(&pinUnblockKey), *reinterpret_cast<hstring const*>(&newPin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange>
{
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

    int32_t WINRT_CALL get_PinType(Windows::Networking::NetworkOperators::MobileBroadbandPinType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinType, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinType));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinType>(this->shim().PinType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinLockState(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinLockState, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPinLockState));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPinLockState>(this->shim().PinLockState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails>
{
    int32_t WINRT_CALL get_PinLockStateChanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinLockStateChanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange>>(this->shim().PinLockStateChanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinManager> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinManager>
{
    int32_t WINRT_CALL get_SupportedPins(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPins, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinType>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandPinType>>(this->shim().SupportedPins());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPin(Windows::Networking::NetworkOperators::MobileBroadbandPinType pinType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPin, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandPin), Windows::Networking::NetworkOperators::MobileBroadbandPinType const&);
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandPin>(this->shim().GetPin(*reinterpret_cast<Windows::Networking::NetworkOperators::MobileBroadbandPinType const*>(&pinType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult>
{
    int32_t WINRT_CALL get_IsSuccessful(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuccessful, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuccessful());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttemptsRemaining(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttemptsRemaining, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AttemptsRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange>
{
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

    int32_t WINRT_CALL get_RadioState(Windows::Networking::NetworkOperators::MobileBroadbandRadioState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadioState, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandRadioState));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandRadioState>(this->shim().RadioState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails>
{
    int32_t WINRT_CALL get_RadioStateChanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadioStateChanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange>>(this->shim().RadioStateChanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandSarManager> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandSarManager>
{
    int32_t WINRT_CALL get_IsBackoffEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBackoffEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBackoffEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWiFiHardwareIntegrated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWiFiHardwareIntegrated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWiFiHardwareIntegrated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSarControlledByHardware(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSarControlledByHardware, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSarControlledByHardware());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Antennas(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Antennas, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar>>(this->shim().Antennas());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HysteresisTimerPeriod(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HysteresisTimerPeriod, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().HysteresisTimerPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TransmissionStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransmissionStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransmissionStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::NetworkOperators::MobileBroadbandSarManager, Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransmissionStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransmissionStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransmissionStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL EnableBackoffAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableBackoffAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().EnableBackoffAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableBackoffAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableBackoffAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DisableBackoffAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetConfigurationAsync(void* antennas, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetConfigurationAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> const*>(&antennas)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RevertSarToHardwareControlAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RevertSarToHardwareControlAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RevertSarToHardwareControlAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTransmissionStateChangedHysteresisAsync(Windows::Foundation::TimeSpan timerPeriod, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTransmissionStateChangedHysteresisAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetTransmissionStateChangedHysteresisAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timerPeriod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsTransmittingAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsTransmittingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsTransmittingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartTransmissionStateMonitoring() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTransmissionStateMonitoring, WINRT_WRAP(void));
            this->shim().StartTransmissionStateMonitoring();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopTransmissionStateMonitoring() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopTransmissionStateMonitoring, WINRT_WRAP(void));
            this->shim().StopTransmissionStateMonitoring();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs>
{
    int32_t WINRT_CALL get_IsTransmitting(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransmitting, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransmitting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandUicc> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandUicc>
{
    int32_t WINRT_CALL get_SimIccId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimIccId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SimIccId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUiccAppsAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUiccAppsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult>>(this->shim().GetUiccAppsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::UiccAppKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Networking::NetworkOperators::UiccAppKind));
            *value = detach_from<Windows::Networking::NetworkOperators::UiccAppKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRecordDetailsAsync(void* uiccFilePath, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecordDetailsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult>), Windows::Foundation::Collections::IIterable<uint32_t> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult>>(this->shim().GetRecordDetailsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<uint32_t> const*>(&uiccFilePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadRecordAsync(void* uiccFilePath, int32_t recordIndex, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadRecordAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult>), Windows::Foundation::Collections::IIterable<uint32_t> const, int32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult>>(this->shim().ReadRecordAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<uint32_t> const*>(&uiccFilePath), recordIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus>(this->shim().Status());
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
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Networking::NetworkOperators::UiccAppRecordKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Networking::NetworkOperators::UiccAppRecordKind));
            *value = detach_from<Windows::Networking::NetworkOperators::UiccAppRecordKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RecordCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordSize(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordSize, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RecordSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadAccessCondition(Windows::Networking::NetworkOperators::UiccAccessCondition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadAccessCondition, WINRT_WRAP(Windows::Networking::NetworkOperators::UiccAccessCondition));
            *value = detach_from<Windows::Networking::NetworkOperators::UiccAccessCondition>(this->shim().ReadAccessCondition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteAccessCondition(Windows::Networking::NetworkOperators::UiccAccessCondition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteAccessCondition, WINRT_WRAP(Windows::Networking::NetworkOperators::UiccAccessCondition));
            *value = detach_from<Windows::Networking::NetworkOperators::UiccAccessCondition>(this->shim().WriteAccessCondition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult> : produce_base<D, Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::MobileBroadbandUiccAppOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UiccApps(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UiccApps, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::MobileBroadbandUiccApp>>(this->shim().UiccApps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails>
{
    int32_t WINRT_CALL get_NotificationKind(Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationKind, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind));
            *value = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorDataUsageNotificationKind>(this->shim().NotificationKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails>
{
    int32_t WINRT_CALL get_NotificationType(Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotificationType, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType));
            *value = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorEventMessageType>(this->shim().NotificationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EncodingType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodingType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EncodingType());
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
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RuleId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RuleId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RuleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmsMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmsMessage, WINRT_WRAP(Windows::Devices::Sms::ISmsMessage));
            *value = detach_from<Windows::Devices::Sms::ISmsMessage>(this->shim().SmsMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration>
{
    int32_t WINRT_CALL get_Ssid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ssid, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Ssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Ssid(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ssid, WINRT_WRAP(void), hstring const&);
            this->shim().Ssid(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Passphrase(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Passphrase, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Passphrase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Passphrase(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Passphrase, WINRT_WRAP(void), hstring const&);
            this->shim().Passphrase(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient>
{
    int32_t WINRT_CALL get_MacAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MacAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MacAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HostNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>>(this->shim().HostNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager>
{
    int32_t WINRT_CALL GetTetheringClients(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTetheringClients, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient>>(this->shim().GetTetheringClients());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck>
{
    int32_t WINRT_CALL AuthorizeTethering(bool allow, void* entitlementFailureReason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorizeTethering, WINRT_WRAP(void), bool, hstring const&);
            this->shim().AuthorizeTethering(allow, *reinterpret_cast<hstring const*>(&entitlementFailureReason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager>
{
    int32_t WINRT_CALL get_MaxClientCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxClientCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxClientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ClientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TetheringOperationalState(Windows::Networking::NetworkOperators::TetheringOperationalState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TetheringOperationalState, WINRT_WRAP(Windows::Networking::NetworkOperators::TetheringOperationalState));
            *value = detach_from<Windows::Networking::NetworkOperators::TetheringOperationalState>(this->shim().TetheringOperationalState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentAccessPointConfiguration(void** configuration) noexcept final
    {
        try
        {
            *configuration = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentAccessPointConfiguration, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration));
            *configuration = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration>(this->shim().GetCurrentAccessPointConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureAccessPointAsync(void* configuration, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureAccessPointAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ConfigureAccessPointAsync(*reinterpret_cast<Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartTetheringAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTetheringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>>(this->shim().StartTetheringAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopTetheringAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopTetheringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult>>(this->shim().StopTetheringAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>
{
    int32_t WINRT_CALL GetTetheringCapability(void* networkAccountId, Windows::Networking::NetworkOperators::TetheringCapability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTetheringCapability, WINRT_WRAP(Windows::Networking::NetworkOperators::TetheringCapability), hstring const&);
            *value = detach_from<Windows::Networking::NetworkOperators::TetheringCapability>(this->shim().GetTetheringCapability(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ppManager) noexcept final
    {
        try
        {
            *ppManager = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNetworkAccountId, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager), hstring const&);
            *ppManager = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>(this->shim().CreateFromNetworkAccountId(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>
{
    int32_t WINRT_CALL GetTetheringCapabilityFromConnectionProfile(void* profile, Windows::Networking::NetworkOperators::TetheringCapability* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTetheringCapabilityFromConnectionProfile, WINRT_WRAP(Windows::Networking::NetworkOperators::TetheringCapability), Windows::Networking::Connectivity::ConnectionProfile const&);
            *result = detach_from<Windows::Networking::NetworkOperators::TetheringCapability>(this->shim().GetTetheringCapabilityFromConnectionProfile(*reinterpret_cast<Windows::Networking::Connectivity::ConnectionProfile const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromConnectionProfile(void* profile, void** ppManager) noexcept final
    {
        try
        {
            *ppManager = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromConnectionProfile, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager), Windows::Networking::Connectivity::ConnectionProfile const&);
            *ppManager = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>(this->shim().CreateFromConnectionProfile(*reinterpret_cast<Windows::Networking::Connectivity::ConnectionProfile const*>(&profile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>
{
    int32_t WINRT_CALL CreateFromConnectionProfileWithTargetAdapter(void* profile, void* adapter, void** ppManager) noexcept final
    {
        try
        {
            *ppManager = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromConnectionProfile, WINRT_WRAP(Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager), Windows::Networking::Connectivity::ConnectionProfile const&, Windows::Networking::Connectivity::NetworkAdapter const&);
            *ppManager = detach_from<Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager>(this->shim().CreateFromConnectionProfile(*reinterpret_cast<Windows::Networking::Connectivity::ConnectionProfile const*>(&profile), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult> : produce_base<D, Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::NetworkOperators::TetheringOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::NetworkOperators::TetheringOperationStatus));
            *value = detach_from<Windows::Networking::NetworkOperators::TetheringOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdditionalErrorMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdditionalErrorMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AdditionalErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults> : produce_base<D, Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults>
{
    int32_t WINRT_CALL get_AllElementsProvisioned(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllElementsProvisioned, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllElementsProvisioned());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProvisionResultsXml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionResultsXml, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProvisionResultsXml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IProvisionedProfile> : produce_base<D, Windows::Networking::NetworkOperators::IProvisionedProfile>
{
    int32_t WINRT_CALL UpdateCost(Windows::Networking::Connectivity::NetworkCostType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateCost, WINRT_WRAP(void), Windows::Networking::Connectivity::NetworkCostType const&);
            this->shim().UpdateCost(*reinterpret_cast<Windows::Networking::Connectivity::NetworkCostType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateUsage(struct struct_Windows_Networking_NetworkOperators_ProfileUsage value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateUsage, WINRT_WRAP(void), Windows::Networking::NetworkOperators::ProfileUsage const&);
            this->shim().UpdateUsage(*reinterpret_cast<Windows::Networking::NetworkOperators::ProfileUsage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IProvisioningAgent> : produce_base<D, Windows::Networking::NetworkOperators::IProvisioningAgent>
{
    int32_t WINRT_CALL ProvisionFromXmlDocumentAsync(void* provisioningXmlDocument, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionFromXmlDocumentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults>>(this->shim().ProvisionFromXmlDocumentAsync(*reinterpret_cast<hstring const*>(&provisioningXmlDocument)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProvisionedProfile(Windows::Networking::NetworkOperators::ProfileMediaType mediaType, void* profileName, void** provisionedProfile) noexcept final
    {
        try
        {
            *provisionedProfile = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProvisionedProfile, WINRT_WRAP(Windows::Networking::NetworkOperators::ProvisionedProfile), Windows::Networking::NetworkOperators::ProfileMediaType const&, hstring const&);
            *provisionedProfile = detach_from<Windows::Networking::NetworkOperators::ProvisionedProfile>(this->shim().GetProvisionedProfile(*reinterpret_cast<Windows::Networking::NetworkOperators::ProfileMediaType const*>(&mediaType), *reinterpret_cast<hstring const*>(&profileName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods> : produce_base<D, Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>
{
    int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** provisioningAgent) noexcept final
    {
        try
        {
            *provisioningAgent = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNetworkAccountId, WINRT_WRAP(Windows::Networking::NetworkOperators::ProvisioningAgent), hstring const&);
            *provisioningAgent = detach_from<Windows::Networking::NetworkOperators::ProvisioningAgent>(this->shim().CreateFromNetworkAccountId(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails> : produce_base<D, Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails>
{
    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AllowTethering() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowTethering, WINRT_WRAP(void));
            this->shim().AllowTethering();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DenyTethering(void* entitlementFailureReason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DenyTethering, WINRT_WRAP(void), hstring const&);
            this->shim().DenyTethering(*reinterpret_cast<hstring const*>(&entitlementFailureReason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IUssdMessage> : produce_base<D, Windows::Networking::NetworkOperators::IUssdMessage>
{
    int32_t WINRT_CALL get_DataCodingScheme(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataCodingScheme, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().DataCodingScheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataCodingScheme(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataCodingScheme, WINRT_WRAP(void), uint8_t);
            this->shim().DataCodingScheme(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPayload(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPayload, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().GetPayload());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPayload(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPayload, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetPayload(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PayloadAsText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayloadAsText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PayloadAsText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PayloadAsText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PayloadAsText, WINRT_WRAP(void), hstring const&);
            this->shim().PayloadAsText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IUssdMessageFactory> : produce_base<D, Windows::Networking::NetworkOperators::IUssdMessageFactory>
{
    int32_t WINRT_CALL CreateMessage(void* messageText, void** ussdMessage) noexcept final
    {
        try
        {
            *ussdMessage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMessage, WINRT_WRAP(Windows::Networking::NetworkOperators::UssdMessage), hstring const&);
            *ussdMessage = detach_from<Windows::Networking::NetworkOperators::UssdMessage>(this->shim().CreateMessage(*reinterpret_cast<hstring const*>(&messageText)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IUssdReply> : produce_base<D, Windows::Networking::NetworkOperators::IUssdReply>
{
    int32_t WINRT_CALL get_ResultCode(Windows::Networking::NetworkOperators::UssdResultCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultCode, WINRT_WRAP(Windows::Networking::NetworkOperators::UssdResultCode));
            *value = detach_from<Windows::Networking::NetworkOperators::UssdResultCode>(this->shim().ResultCode());
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
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Networking::NetworkOperators::UssdMessage));
            *value = detach_from<Windows::Networking::NetworkOperators::UssdMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IUssdSession> : produce_base<D, Windows::Networking::NetworkOperators::IUssdSession>
{
    int32_t WINRT_CALL SendMessageAndGetReplyAsync(void* message, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAndGetReplyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::UssdReply>), Windows::Networking::NetworkOperators::UssdMessage const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::NetworkOperators::UssdReply>>(this->shim().SendMessageAndGetReplyAsync(*reinterpret_cast<Windows::Networking::NetworkOperators::UssdMessage const*>(&message)));
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
};

template <typename D>
struct produce<D, Windows::Networking::NetworkOperators::IUssdSessionStatics> : produce_base<D, Windows::Networking::NetworkOperators::IUssdSessionStatics>
{
    int32_t WINRT_CALL CreateFromNetworkAccountId(void* networkAccountId, void** ussdSession) noexcept final
    {
        try
        {
            *ussdSession = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNetworkAccountId, WINRT_WRAP(Windows::Networking::NetworkOperators::UssdSession), hstring const&);
            *ussdSession = detach_from<Windows::Networking::NetworkOperators::UssdSession>(this->shim().CreateFromNetworkAccountId(*reinterpret_cast<hstring const*>(&networkAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromNetworkInterfaceId(void* networkInterfaceId, void** ussdSession) noexcept final
    {
        try
        {
            *ussdSession = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromNetworkInterfaceId, WINRT_WRAP(Windows::Networking::NetworkOperators::UssdSession), hstring const&);
            *ussdSession = detach_from<Windows::Networking::NetworkOperators::UssdSession>(this->shim().CreateFromNetworkInterfaceId(*reinterpret_cast<hstring const*>(&networkInterfaceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::NetworkOperators {

inline Windows::Networking::NetworkOperators::ESimServiceInfo ESimManager::ServiceInfo()
{
    return impl::call_factory<ESimManager, Windows::Networking::NetworkOperators::IESimManagerStatics>([&](auto&& f) { return f.ServiceInfo(); });
}

inline Windows::Networking::NetworkOperators::ESimWatcher ESimManager::TryCreateESimWatcher()
{
    return impl::call_factory<ESimManager, Windows::Networking::NetworkOperators::IESimManagerStatics>([&](auto&& f) { return f.TryCreateESimWatcher(); });
}

inline winrt::event_token ESimManager::ServiceInfoChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<ESimManager, Windows::Networking::NetworkOperators::IESimManagerStatics>([&](auto&& f) { return f.ServiceInfoChanged(handler); });
}

inline ESimManager::ServiceInfoChanged_revoker ESimManager::ServiceInfoChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<ESimManager, Windows::Networking::NetworkOperators::IESimManagerStatics>();
    return { f, f.ServiceInfoChanged(handler) };
}

inline void ESimManager::ServiceInfoChanged(winrt::event_token const& token)
{
    impl::call_factory<ESimManager, Windows::Networking::NetworkOperators::IESimManagerStatics>([&](auto&& f) { return f.ServiceInfoChanged(token); });
}

inline Windows::Foundation::IAsyncOperation<bool> FdnAccessManager::RequestUnlockAsync(param::hstring const& contactListId)
{
    return impl::call_factory<FdnAccessManager, Windows::Networking::NetworkOperators::IFdnAccessManagerStatics>([&](auto&& f) { return f.RequestUnlockAsync(contactListId); });
}

inline bool HotspotAuthenticationContext::TryGetAuthenticationContext(param::hstring const& evenToken, Windows::Networking::NetworkOperators::HotspotAuthenticationContext& context)
{
    return impl::call_factory<HotspotAuthenticationContext, Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics>([&](auto&& f) { return f.TryGetAuthenticationContext(evenToken, context); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownCSimFilePaths::EFSpn()
{
    return impl::call_factory<KnownCSimFilePaths, Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>([&](auto&& f) { return f.EFSpn(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownCSimFilePaths::Gid1()
{
    return impl::call_factory<KnownCSimFilePaths, Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>([&](auto&& f) { return f.Gid1(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownCSimFilePaths::Gid2()
{
    return impl::call_factory<KnownCSimFilePaths, Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics>([&](auto&& f) { return f.Gid2(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownRuimFilePaths::EFSpn()
{
    return impl::call_factory<KnownRuimFilePaths, Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>([&](auto&& f) { return f.EFSpn(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownRuimFilePaths::Gid1()
{
    return impl::call_factory<KnownRuimFilePaths, Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>([&](auto&& f) { return f.Gid1(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownRuimFilePaths::Gid2()
{
    return impl::call_factory<KnownRuimFilePaths, Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics>([&](auto&& f) { return f.Gid2(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownSimFilePaths::EFOns()
{
    return impl::call_factory<KnownSimFilePaths, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>([&](auto&& f) { return f.EFOns(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownSimFilePaths::EFSpn()
{
    return impl::call_factory<KnownSimFilePaths, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>([&](auto&& f) { return f.EFSpn(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownSimFilePaths::Gid1()
{
    return impl::call_factory<KnownSimFilePaths, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>([&](auto&& f) { return f.Gid1(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownSimFilePaths::Gid2()
{
    return impl::call_factory<KnownSimFilePaths, Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics>([&](auto&& f) { return f.Gid2(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownUSimFilePaths::EFSpn()
{
    return impl::call_factory<KnownUSimFilePaths, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>([&](auto&& f) { return f.EFSpn(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownUSimFilePaths::EFOpl()
{
    return impl::call_factory<KnownUSimFilePaths, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>([&](auto&& f) { return f.EFOpl(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownUSimFilePaths::EFPnn()
{
    return impl::call_factory<KnownUSimFilePaths, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>([&](auto&& f) { return f.EFPnn(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownUSimFilePaths::Gid1()
{
    return impl::call_factory<KnownUSimFilePaths, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>([&](auto&& f) { return f.Gid1(); });
}

inline Windows::Foundation::Collections::IVectorView<uint32_t> KnownUSimFilePaths::Gid2()
{
    return impl::call_factory<KnownUSimFilePaths, Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics>([&](auto&& f) { return f.Gid2(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> MobileBroadbandAccount::AvailableNetworkAccountIds()
{
    return impl::call_factory<MobileBroadbandAccount, Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>([&](auto&& f) { return f.AvailableNetworkAccountIds(); });
}

inline Windows::Networking::NetworkOperators::MobileBroadbandAccount MobileBroadbandAccount::CreateFromNetworkAccountId(param::hstring const& networkAccountId)
{
    return impl::call_factory<MobileBroadbandAccount, Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics>([&](auto&& f) { return f.CreateFromNetworkAccountId(networkAccountId); });
}

inline MobileBroadbandAccountWatcher::MobileBroadbandAccountWatcher() :
    MobileBroadbandAccountWatcher(impl::call_factory<MobileBroadbandAccountWatcher>([](auto&& f) { return f.template ActivateInstance<MobileBroadbandAccountWatcher>(); }))
{}

inline MobileBroadbandAntennaSar::MobileBroadbandAntennaSar(int32_t antennaIndex, int32_t sarBackoffIndex) :
    MobileBroadbandAntennaSar(impl::call_factory<MobileBroadbandAntennaSar, Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory>([&](auto&& f) { return f.CreateWithIndex(antennaIndex, sarBackoffIndex); }))
{}

inline hstring MobileBroadbandModem::GetDeviceSelector()
{
    return impl::call_factory<MobileBroadbandModem, Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Networking::NetworkOperators::MobileBroadbandModem MobileBroadbandModem::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<MobileBroadbandModem, Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>([&](auto&& f) { return f.FromId(deviceId); });
}

inline Windows::Networking::NetworkOperators::MobileBroadbandModem MobileBroadbandModem::GetDefault()
{
    return impl::call_factory<MobileBroadbandModem, Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline MobileBroadbandModemIsolation::MobileBroadbandModemIsolation(param::hstring const& modemDeviceId, param::hstring const& ruleGroupId) :
    MobileBroadbandModemIsolation(impl::call_factory<MobileBroadbandModemIsolation, Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory>([&](auto&& f) { return f.Create(modemDeviceId, ruleGroupId); }))
{}

inline NetworkOperatorTetheringAccessPointConfiguration::NetworkOperatorTetheringAccessPointConfiguration() :
    NetworkOperatorTetheringAccessPointConfiguration(impl::call_factory<NetworkOperatorTetheringAccessPointConfiguration>([](auto&& f) { return f.template ActivateInstance<NetworkOperatorTetheringAccessPointConfiguration>(); }))
{}

inline Windows::Networking::NetworkOperators::TetheringCapability NetworkOperatorTetheringManager::GetTetheringCapability(param::hstring const& networkAccountId)
{
    return impl::call_factory<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>([&](auto&& f) { return f.GetTetheringCapability(networkAccountId); });
}

inline Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager NetworkOperatorTetheringManager::CreateFromNetworkAccountId(param::hstring const& networkAccountId)
{
    return impl::call_factory<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics>([&](auto&& f) { return f.CreateFromNetworkAccountId(networkAccountId); });
}

inline Windows::Networking::NetworkOperators::TetheringCapability NetworkOperatorTetheringManager::GetTetheringCapabilityFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile)
{
    return impl::call_factory<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>([&](auto&& f) { return f.GetTetheringCapabilityFromConnectionProfile(profile); });
}

inline Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager NetworkOperatorTetheringManager::CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile)
{
    return impl::call_factory<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2>([&](auto&& f) { return f.CreateFromConnectionProfile(profile); });
}

inline Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager NetworkOperatorTetheringManager::CreateFromConnectionProfile(Windows::Networking::Connectivity::ConnectionProfile const& profile, Windows::Networking::Connectivity::NetworkAdapter const& adapter)
{
    return impl::call_factory<NetworkOperatorTetheringManager, Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3>([&](auto&& f) { return f.CreateFromConnectionProfile(profile, adapter); });
}

inline ProvisioningAgent::ProvisioningAgent() :
    ProvisioningAgent(impl::call_factory<ProvisioningAgent>([](auto&& f) { return f.template ActivateInstance<ProvisioningAgent>(); }))
{}

inline Windows::Networking::NetworkOperators::ProvisioningAgent ProvisioningAgent::CreateFromNetworkAccountId(param::hstring const& networkAccountId)
{
    return impl::call_factory<ProvisioningAgent, Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods>([&](auto&& f) { return f.CreateFromNetworkAccountId(networkAccountId); });
}

inline UssdMessage::UssdMessage(param::hstring const& messageText) :
    UssdMessage(impl::call_factory<UssdMessage, Windows::Networking::NetworkOperators::IUssdMessageFactory>([&](auto&& f) { return f.CreateMessage(messageText); }))
{}

inline Windows::Networking::NetworkOperators::UssdSession UssdSession::CreateFromNetworkAccountId(param::hstring const& networkAccountId)
{
    return impl::call_factory<UssdSession, Windows::Networking::NetworkOperators::IUssdSessionStatics>([&](auto&& f) { return f.CreateFromNetworkAccountId(networkAccountId); });
}

inline Windows::Networking::NetworkOperators::UssdSession UssdSession::CreateFromNetworkInterfaceId(param::hstring const& networkInterfaceId)
{
    return impl::call_factory<UssdSession, Windows::Networking::NetworkOperators::IUssdSessionStatics>([&](auto&& f) { return f.CreateFromNetworkInterfaceId(networkInterfaceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESim> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESim> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESim2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESim2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimAddedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimDiscoverEvent> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimDiscoverEvent> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimDiscoverResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimDiscoverResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimDownloadProfileMetadataResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimManagerStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimManagerStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimPolicy> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimPolicy> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimProfile> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimProfile> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimProfileMetadata> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimProfileMetadata> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimProfilePolicy> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimProfilePolicy> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimServiceInfo> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimServiceInfo> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IESimWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IESimWatcher> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IFdnAccessManagerStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IFdnAccessManagerStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContext2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationContextStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IHotspotAuthenticationEventDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IHotspotCredentialsAuthenticationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IKnownCSimFilePathsStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IKnownRuimFilePathsStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IKnownSimFilePathsStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IKnownUSimFilePathsStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount3> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccount3> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAccountWatcher> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSar> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandAntennaSarFactory> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellCdma> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellGsm> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellLte> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellLte> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellTdscdma> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellUmts> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandCellsInfo> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceInformation3> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceService> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceCommandSession> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceDataSession> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceInformation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandDeviceServiceTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem3> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModem3> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemConfiguration2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemIsolationFactory> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandModemStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetwork3> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandNetworkRegistrationStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPco> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPco> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPcoDataChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPin> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPin> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinLockStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandPinOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandRadioStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSarManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandSarManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandTransmissionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUicc> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUicc> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccApp> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppReadRecordResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppRecordDetailsResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IMobileBroadbandUiccAppsResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorDataUsageTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorNotificationEventDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringAccessPointConfiguration> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClient> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringClientManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringEntitlementCheck> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics2> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringManagerStatics3> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::INetworkOperatorTetheringOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IProvisionFromXmlDocumentResults> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IProvisionedProfile> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IProvisionedProfile> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IProvisioningAgent> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IProvisioningAgent> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IProvisioningAgentStaticMethods> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ITetheringEntitlementCheckTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IUssdMessage> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IUssdMessage> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IUssdMessageFactory> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IUssdMessageFactory> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IUssdReply> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IUssdReply> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IUssdSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IUssdSession> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::IUssdSessionStatics> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::IUssdSessionStatics> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESim> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESim> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimAddedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimDiscoverEvent> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimDiscoverEvent> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimDiscoverResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimDiscoverResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimDownloadProfileMetadataResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimPolicy> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimPolicy> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimProfile> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimProfile> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimProfileMetadata> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimProfileMetadata> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimProfilePolicy> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimProfilePolicy> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimServiceInfo> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimServiceInfo> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ESimWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ESimWatcher> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::FdnAccessManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::FdnAccessManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::HotspotAuthenticationContext> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::HotspotAuthenticationContext> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::HotspotAuthenticationEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::HotspotAuthenticationEventDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::HotspotCredentialsAuthenticationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::KnownCSimFilePaths> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::KnownCSimFilePaths> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::KnownRuimFilePaths> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::KnownRuimFilePaths> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::KnownSimFilePaths> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::KnownSimFilePaths> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::KnownUSimFilePaths> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::KnownUSimFilePaths> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccount> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccount> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAccountWatcher> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandAntennaSar> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellCdma> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellGsm> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellLte> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellLte> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellTdscdma> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellUmts> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandCellsInfo> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceInformation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceService> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceService> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceCommandSession> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceDataSession> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceInformation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandDeviceServiceTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModem> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModem> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModemConfiguration> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandModemIsolation> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetwork> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetwork> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandNetworkRegistrationStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPco> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPco> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPcoDataChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPcoDataChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPin> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPin> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinLockStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandPinOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChange> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandRadioStateChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandSarManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandSarManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandTransmissionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUicc> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUicc> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccApp> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppReadRecordResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppRecordDetailsResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::MobileBroadbandUiccAppsResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorDataUsageTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorDataUsageTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorNotificationEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorNotificationEventDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringAccessPointConfiguration> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringClient> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringManager> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::NetworkOperatorTetheringOperationResult> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ProvisionFromXmlDocumentResults> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ProvisionedProfile> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ProvisionedProfile> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::ProvisioningAgent> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::ProvisioningAgent> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::TetheringEntitlementCheckTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::TetheringEntitlementCheckTriggerDetails> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::UssdMessage> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::UssdMessage> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::UssdReply> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::UssdReply> {};
template<> struct hash<winrt::Windows::Networking::NetworkOperators::UssdSession> : winrt::impl::hash_base<winrt::Windows::Networking::NetworkOperators::UssdSession> {};

}
