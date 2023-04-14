// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Globalization.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Devices.AllJoyn.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_IsEnabled(value));
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultAppName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_DefaultAppName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultAppName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_DefaultAppName(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::AppNames() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_AppNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DateOfManufacture() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_DateOfManufacture(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DateOfManufacture(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_DateOfManufacture(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_DefaultDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_DefaultDescription(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::Descriptions() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_Descriptions(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultManufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_DefaultManufacturer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::DefaultManufacturer(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_DefaultManufacturer(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::Manufacturers() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_Manufacturers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::ModelNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_ModelNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::ModelNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_ModelNumber(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::SoftwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_SoftwareVersion(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::SoftwareVersion(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_SoftwareVersion(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::SupportUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_SupportUrl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::SupportUrl(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_SupportUrl(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::AppId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAboutData<D>::AppId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutData)->put_AppId(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_Status(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::AJSoftwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_AJSoftwareVersion(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::AppId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::DateOfManufacture() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_DateOfManufacture(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Language consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::DefaultLanguage() const
{
    Windows::Globalization::Language value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_DefaultLanguage(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::HardwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_HardwareVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::ModelNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_ModelNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::SoftwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_SoftwareVersion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::SupportedLanguages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_SupportedLanguages(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::SupportUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_SupportUrl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::AppName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_AppName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::DeviceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_DeviceName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAboutDataView<D>::Manufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataView)->get_Manufacturer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> consume_Windows_Devices_AllJoyn_IAllJoynAboutDataViewStatics<D>::GetDataBySessionPortAsync(param::hstring const& uniqueName, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics)->GetDataBySessionPortAsync(get_abi(uniqueName), get_abi(busAttachment), sessionPort, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> consume_Windows_Devices_AllJoyn_IAllJoynAboutDataViewStatics<D>::GetDataBySessionPortAsync(param::hstring const& uniqueName, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort, Windows::Globalization::Language const& language) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics)->GetDataBySessionPortWithLanguageAsync(get_abi(uniqueName), get_abi(busAttachment), sessionPort, get_abi(language), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoiner<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner)->Accept());
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::SessionPort() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->get_SessionPort(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynTrafficType consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::TrafficType() const
{
    Windows::Devices::AllJoyn::AllJoynTrafficType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->get_TrafficType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::SamePhysicalNode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->get_SamePhysicalNode(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::SameNetwork() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->get_SameNetwork(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgs<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs)->Accept());
}

template <typename D> Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs consume_Windows_Devices_AllJoyn_IAllJoynAcceptSessionJoinerEventArgsFactory<D>::Create(param::hstring const& uniqueName, uint16_t sessionPort, Windows::Devices::AllJoyn::AllJoynTrafficType const& trafficType, uint8_t proximity, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner const& acceptSessionJoiner) const
{
    Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory)->Create(get_abi(uniqueName), sessionPort, get_abi(trafficType), proximity, get_abi(acceptSessionJoiner), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism consume_Windows_Devices_AllJoyn_IAllJoynAuthenticationCompleteEventArgs<D>::AuthenticationMechanism() const
{
    Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs)->get_AuthenticationMechanism(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynAuthenticationCompleteEventArgs<D>::PeerUniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs)->get_PeerUniqueName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_AllJoyn_IAllJoynAuthenticationCompleteEventArgs<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynAboutData consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AboutData() const
{
    Windows::Devices::AllJoyn::AllJoynAboutData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->get_AboutData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::ConnectionSpecification() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->get_ConnectionSpecification(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusAttachmentState consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::State() const
{
    Windows::Devices::AllJoyn::AllJoynBusAttachmentState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<int32_t> consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::PingAsync(param::hstring const& uniqueName) const
{
    Windows::Foundation::IAsyncOperation<int32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->PingAsync(get_abi(uniqueName), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::Connect() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->Connect());
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::Disconnect() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->Disconnect());
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::StateChanged_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->remove_StateChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism> consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AuthenticationMechanisms() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->get_AuthenticationMechanisms(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->add_CredentialsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsRequested_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CredentialsRequested_revoker>(this, CredentialsRequested(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->remove_CredentialsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsVerificationRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->add_CredentialsVerificationRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsVerificationRequested_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsVerificationRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CredentialsVerificationRequested_revoker>(this, CredentialsVerificationRequested(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::CredentialsVerificationRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->remove_CredentialsVerificationRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AuthenticationComplete(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->add_AuthenticationComplete(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AuthenticationComplete_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AuthenticationComplete(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AuthenticationComplete_revoker>(this, AuthenticationComplete(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment<D>::AuthenticationComplete(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment)->remove_AuthenticationComplete(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::GetAboutDataAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->GetAboutDataAsync(get_abi(serviceInfo), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::GetAboutDataAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo, Windows::Globalization::Language const& language) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->GetAboutDataWithLanguageAsync(get_abi(serviceInfo), get_abi(language), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::AcceptSessionJoinerRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->add_AcceptSessionJoinerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::AcceptSessionJoinerRequested_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::AcceptSessionJoinerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AcceptSessionJoinerRequested_revoker>(this, AcceptSessionJoinerRequested(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::AcceptSessionJoinerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->remove_AcceptSessionJoinerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::SessionJoined(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->add_SessionJoined(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::SessionJoined_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::SessionJoined(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionJoined_revoker>(this, SessionJoined(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusAttachment2<D>::SessionJoined(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachment2)->remove_SessionJoined(get_abi(token)));
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusAttachment consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentFactory<D>::Create(param::hstring const& connectionSpecification) const
{
    Windows::Devices::AllJoyn::AllJoynBusAttachment result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory)->Create(get_abi(connectionSpecification), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusAttachmentState consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStateChangedEventArgs<D>::State() const
{
    Windows::Devices::AllJoyn::AllJoynBusAttachmentState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStateChangedEventArgs<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs)->get_Status(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusAttachment consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStatics<D>::GetDefault() const
{
    Windows::Devices::AllJoyn::AllJoynBusAttachment defaultBusAttachment{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics)->GetDefault(put_abi(defaultBusAttachment)));
    return defaultBusAttachment;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_AllJoyn_IAllJoynBusAttachmentStatics<D>::GetWatcher(param::iterable<hstring> const& requiredInterfaces) const
{
    Windows::Devices::Enumeration::DeviceWatcher deviceWatcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics)->GetWatcher(get_abi(requiredInterfaces), put_abi(deviceWatcher)));
    return deviceWatcher;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->Start());
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->Stop());
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::AddProducer(Windows::Devices::AllJoyn::IAllJoynProducer const& producer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->AddProducer(get_abi(producer)));
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusAttachment consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::BusAttachment() const
{
    Windows::Devices::AllJoyn::AllJoynBusAttachment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->get_BusAttachment(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSession consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Session() const
{
    Windows::Devices::AllJoyn::AllJoynSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->get_Session(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusObject, Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Stopped_revoker consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusObject, Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynBusObject<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObject)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusObject consume_Windows_Devices_AllJoyn_IAllJoynBusObjectFactory<D>::Create(param::hstring const& objectPath) const
{
    Windows::Devices::AllJoyn::AllJoynBusObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObjectFactory)->Create(get_abi(objectPath), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusObject consume_Windows_Devices_AllJoyn_IAllJoynBusObjectFactory<D>::CreateWithBusAttachment(param::hstring const& objectPath, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment) const
{
    Windows::Devices::AllJoyn::AllJoynBusObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObjectFactory)->CreateWithBusAttachment(get_abi(objectPath), get_abi(busAttachment), put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgs<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs)->get_Status(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynBusObjectStoppedEventArgsFactory<D>::Create(int32_t status) const
{
    Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory)->Create(status, put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::AuthenticationMechanism() const
{
    Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->get_AuthenticationMechanism(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::Certificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->get_Certificate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::Certificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->put_Certificate(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::PasswordCredential() const
{
    Windows::Security::Credentials::PasswordCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->get_PasswordCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::PasswordCredential(Windows::Security::Credentials::PasswordCredential const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->put_PasswordCredential(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::Timeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->get_Timeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynCredentials<D>::Timeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentials)->put_Timeout(get_abi(value)));
}

template <typename D> uint16_t consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>::AttemptCount() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs)->get_AttemptCount(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynCredentials consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>::Credentials() const
{
    Windows::Devices::AllJoyn::AllJoynCredentials value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs)->get_Credentials(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>::PeerUniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs)->get_PeerUniqueName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>::RequestedUserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs)->get_RequestedUserName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_AllJoyn_IAllJoynCredentialsRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::AuthenticationMechanism() const
{
    Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_AuthenticationMechanism(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::PeerUniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_PeerUniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::PeerCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_PeerCertificate(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketSslErrorSeverity consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::PeerCertificateErrorSeverity() const
{
    Windows::Networking::Sockets::SocketSslErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_PeerCertificateErrorSeverity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::PeerCertificateErrors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_PeerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::PeerIntermediateCertificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->get_PeerIntermediateCertificates(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->Accept());
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_AllJoyn_IAllJoynCredentialsVerificationRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynMessageInfo<D>::SenderUniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynMessageInfo)->get_SenderUniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynMessageInfo consume_Windows_Devices_AllJoyn_IAllJoynMessageInfoFactory<D>::Create(param::hstring const& senderUniqueName) const
{
    Windows::Devices::AllJoyn::AllJoynMessageInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory)->Create(get_abi(senderUniqueName), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynProducer<D>::SetBusObject(Windows::Devices::AllJoyn::AllJoynBusObject const& busObject) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynProducer)->SetBusObject(get_abi(busObject)));
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgs<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs)->get_Status(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynProducerStoppedEventArgsFactory<D>::Create(int32_t status) const
{
    Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory)->Create(status, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynServiceInfo<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfo)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynServiceInfo<D>::ObjectPath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfo)->get_ObjectPath(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_AllJoyn_IAllJoynServiceInfo<D>::SessionPort() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfo)->get_SessionPort(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynServiceInfo consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoFactory<D>::Create(param::hstring const& uniqueName, param::hstring const& objectPath, uint16_t sessionPort) const
{
    Windows::Devices::AllJoyn::AllJoynServiceInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory)->Create(get_abi(uniqueName), get_abi(objectPath), sessionPort, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgs<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoRemovedEventArgsFactory<D>::Create(param::hstring const& uniqueName) const
{
    Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory)->Create(get_abi(uniqueName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynServiceInfo> consume_Windows_Devices_AllJoyn_IAllJoynServiceInfoStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynServiceInfo> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Id() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->get_Id(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->get_Status(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<int32_t> consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::RemoveMemberAsync(param::hstring const& uniqueName) const
{
    Windows::Foundation::IAsyncOperation<int32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->RemoveMemberAsync(get_abi(uniqueName), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberAdded(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->add_MemberAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberAdded_revoker consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MemberAdded_revoker>(this, MemberAdded(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->remove_MemberAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberRemoved(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->add_MemberRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberRemoved_revoker consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MemberRemoved_revoker>(this, MemberRemoved(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::MemberRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->remove_MemberRemoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Lost(Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->add_Lost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Lost_revoker consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Lost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Lost_revoker>(this, Lost(handler));
}

template <typename D> void consume_Windows_Devices_AllJoyn_IAllJoynSession<D>::Lost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSession)->remove_Lost(get_abi(token)));
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSession consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgs<D>::Session() const
{
    Windows::Devices::AllJoyn::AllJoynSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynSessionJoinedEventArgsFactory<D>::Create(Windows::Devices::AllJoyn::AllJoynSession const& session) const
{
    Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory)->Create(get_abi(session), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSessionLostReason consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgs<D>::Reason() const
{
    Windows::Devices::AllJoyn::AllJoynSessionLostReason value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs consume_Windows_Devices_AllJoyn_IAllJoynSessionLostEventArgsFactory<D>::Create(Windows::Devices::AllJoyn::AllJoynSessionLostReason const& reason) const
{
    Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory)->Create(get_abi(reason), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgs<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberAddedEventArgsFactory<D>::Create(param::hstring const& uniqueName) const
{
    Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory)->Create(get_abi(uniqueName), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgs<D>::UniqueName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs)->get_UniqueName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynSessionMemberRemovedEventArgsFactory<D>::Create(param::hstring const& uniqueName) const
{
    Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory)->Create(get_abi(uniqueName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> consume_Windows_Devices_AllJoyn_IAllJoynSessionStatics<D>::GetFromServiceInfoAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionStatics)->GetFromServiceInfoAsync(get_abi(serviceInfo), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> consume_Windows_Devices_AllJoyn_IAllJoynSessionStatics<D>::GetFromServiceInfoAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynSessionStatics)->GetFromServiceInfoAndBusAttachmentAsync(get_abi(serviceInfo), get_abi(busAttachment), put_abi(operation)));
    return operation;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::Ok() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_Ok(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::Fail() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_Fail(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::OperationTimedOut() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_OperationTimedOut(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::OtherEndClosed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_OtherEndClosed(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::ConnectionRefused() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_ConnectionRefused(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::AuthenticationFailed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_AuthenticationFailed(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::AuthenticationRejectedByUser() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_AuthenticationRejectedByUser(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::SslConnectFailed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_SslConnectFailed(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::SslIdentityVerificationFailed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_SslIdentityVerificationFailed(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InsufficientSecurity() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InsufficientSecurity(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument1() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument1(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument2() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument2(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument3() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument3(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument4() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument4(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument5() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument5(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument6() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument6(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument7() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument7(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynStatusStatics<D>::InvalidArgument8() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynStatusStatics)->get_InvalidArgument8(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgs<D>::Status() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs)->get_Status(&value));
    return value;
}

template <typename D> Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs consume_Windows_Devices_AllJoyn_IAllJoynWatcherStoppedEventArgsFactory<D>::Create(int32_t status) const
{
    Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory)->Create(status, put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAboutData> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAboutData>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultAppName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultAppName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DefaultAppName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultAppName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultAppName, WINRT_WRAP(void), hstring const&);
            this->shim().DefaultAppName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppNames, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AppNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateOfManufacture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateOfManufacture, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DateOfManufacture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DateOfManufacture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateOfManufacture, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().DateOfManufacture(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DefaultDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultDescription, WINRT_WRAP(void), hstring const&);
            this->shim().DefaultDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptions, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Descriptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultManufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultManufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DefaultManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultManufacturer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultManufacturer, WINRT_WRAP(void), hstring const&);
            this->shim().DefaultManufacturer(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Manufacturers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Manufacturers, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Manufacturers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ModelNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(void), hstring const&);
            this->shim().ModelNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoftwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SoftwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SoftwareVersion(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareVersion, WINRT_WRAP(void), hstring const&);
            this->shim().SoftwareVersion(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SupportUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportUrl(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportUrl, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SupportUrl(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().AppId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAboutDataView> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAboutDataView>
{
    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AJSoftwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AJSoftwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AJSoftwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateOfManufacture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateOfManufacture, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DateOfManufacture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultLanguage, WINRT_WRAP(Windows::Globalization::Language));
            *value = detach_from<Windows::Globalization::Language>(this->shim().DefaultLanguage());
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

    int32_t WINRT_CALL get_HardwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ModelNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoftwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SoftwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedLanguages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedLanguages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Globalization::Language>>(this->shim().SupportedLanguages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SupportUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceName());
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
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>
{
    int32_t WINRT_CALL GetDataBySessionPortAsync(void* uniqueName, void* busAttachment, uint16_t sessionPort, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataBySessionPortAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>), hstring const, Windows::Devices::AllJoyn::AllJoynBusAttachment const, uint16_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>>(this->shim().GetDataBySessionPortAsync(*reinterpret_cast<hstring const*>(&uniqueName), *reinterpret_cast<Windows::Devices::AllJoyn::AllJoynBusAttachment const*>(&busAttachment), sessionPort));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataBySessionPortWithLanguageAsync(void* uniqueName, void* busAttachment, uint16_t sessionPort, void* language, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataBySessionPortAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>), hstring const, Windows::Devices::AllJoyn::AllJoynBusAttachment const, uint16_t, Windows::Globalization::Language const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>>(this->shim().GetDataBySessionPortAsync(*reinterpret_cast<hstring const*>(&uniqueName), *reinterpret_cast<Windows::Devices::AllJoyn::AllJoynBusAttachment const*>(&busAttachment), sessionPort, *reinterpret_cast<Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner>
{
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
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs>
{
    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionPort(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionPort, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().SessionPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrafficType(Windows::Devices::AllJoyn::AllJoynTrafficType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficType, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynTrafficType));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynTrafficType>(this->shim().TrafficType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SamePhysicalNode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SamePhysicalNode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SamePhysicalNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SameNetwork(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SameNetwork, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SameNetwork());
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
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>
{
    int32_t WINRT_CALL Create(void* uniqueName, uint16_t sessionPort, Windows::Devices::AllJoyn::AllJoynTrafficType trafficType, uint8_t proximity, void* acceptSessionJoiner, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs), hstring const&, uint16_t, Windows::Devices::AllJoyn::AllJoynTrafficType const&, uint8_t, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs>(this->shim().Create(*reinterpret_cast<hstring const*>(&uniqueName), sessionPort, *reinterpret_cast<Windows::Devices::AllJoyn::AllJoynTrafficType const*>(&trafficType), proximity, *reinterpret_cast<Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner const*>(&acceptSessionJoiner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs>
{
    int32_t WINRT_CALL get_AuthenticationMechanism(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationMechanism, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>(this->shim().AuthenticationMechanism());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerUniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerUniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PeerUniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusAttachment> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusAttachment>
{
    int32_t WINRT_CALL get_AboutData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AboutData, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynAboutData));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynAboutData>(this->shim().AboutData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionSpecification(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionSpecification, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConnectionSpecification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Devices::AllJoyn::AllJoynBusAttachmentState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusAttachmentState));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynBusAttachmentState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PingAsync(void* uniqueName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<int32_t>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().PingAsync(*reinterpret_cast<hstring const*>(&uniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Connect() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connect, WINRT_WRAP(void));
            this->shim().Connect();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Disconnect() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnect, WINRT_WRAP(void));
            this->shim().Disconnect();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL get_AuthenticationMechanisms(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationMechanisms, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>>(this->shim().AuthenticationMechanisms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CredentialsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CredentialsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CredentialsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CredentialsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CredentialsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CredentialsVerificationRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialsVerificationRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CredentialsVerificationRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CredentialsVerificationRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CredentialsVerificationRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CredentialsVerificationRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AuthenticationComplete(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationComplete, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationComplete(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AuthenticationComplete(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AuthenticationComplete, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AuthenticationComplete(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusAttachment2> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusAttachment2>
{
    int32_t WINRT_CALL GetAboutDataAsync(void* serviceInfo, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAboutDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>), Windows::Devices::AllJoyn::AllJoynServiceInfo const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>>(this->shim().GetAboutDataAsync(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynServiceInfo const*>(&serviceInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAboutDataWithLanguageAsync(void* serviceInfo, void* language, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAboutDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>), Windows::Devices::AllJoyn::AllJoynServiceInfo const, Windows::Globalization::Language const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView>>(this->shim().GetAboutDataAsync(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynServiceInfo const*>(&serviceInfo), *reinterpret_cast<Windows::Globalization::Language const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AcceptSessionJoinerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptSessionJoinerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AcceptSessionJoinerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AcceptSessionJoinerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AcceptSessionJoinerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AcceptSessionJoinerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SessionJoined(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionJoined, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionJoined(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusAttachment, Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionJoined(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionJoined, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionJoined(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>
{
    int32_t WINRT_CALL Create(void* connectionSpecification, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusAttachment), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynBusAttachment>(this->shim().Create(*reinterpret_cast<hstring const*>(&connectionSpecification)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Devices::AllJoyn::AllJoynBusAttachmentState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusAttachmentState));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynBusAttachmentState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>
{
    int32_t WINRT_CALL GetDefault(void** defaultBusAttachment) noexcept final
    {
        try
        {
            *defaultBusAttachment = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusAttachment));
            *defaultBusAttachment = detach_from<Windows::Devices::AllJoyn::AllJoynBusAttachment>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWatcher(void* requiredInterfaces, void** deviceWatcher) noexcept final
    {
        try
        {
            *deviceWatcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher), Windows::Foundation::Collections::IIterable<hstring> const&);
            *deviceWatcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().GetWatcher(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&requiredInterfaces)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusObject> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusObject>
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

    int32_t WINRT_CALL AddProducer(void* producer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddProducer, WINRT_WRAP(void), Windows::Devices::AllJoyn::IAllJoynProducer const&);
            this->shim().AddProducer(*reinterpret_cast<Windows::Devices::AllJoyn::IAllJoynProducer const*>(&producer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BusAttachment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusAttachment, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusAttachment));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynBusAttachment>(this->shim().BusAttachment());
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
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSession));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusObject, Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynBusObject, Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusObjectFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>
{
    int32_t WINRT_CALL Create(void* objectPath, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusObject), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynBusObject>(this->shim().Create(*reinterpret_cast<hstring const*>(&objectPath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithBusAttachment(void* objectPath, void* busAttachment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithBusAttachment, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusObject), hstring const&, Windows::Devices::AllJoyn::AllJoynBusAttachment const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynBusObject>(this->shim().CreateWithBusAttachment(*reinterpret_cast<hstring const*>(&objectPath), *reinterpret_cast<Windows::Devices::AllJoyn::AllJoynBusAttachment const*>(&busAttachment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs>
{
    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>
{
    int32_t WINRT_CALL Create(int32_t status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs), int32_t);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs>(this->shim().Create(status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynCredentials> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynCredentials>
{
    int32_t WINRT_CALL get_AuthenticationMechanism(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationMechanism, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>(this->shim().AuthenticationMechanism());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Certificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Certificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().Certificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Certificate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Certificate, WINRT_WRAP(void), Windows::Security::Cryptography::Certificates::Certificate const&);
            this->shim().Certificate(*reinterpret_cast<Windows::Security::Cryptography::Certificates::Certificate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PasswordCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *value = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().PasswordCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PasswordCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PasswordCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().PasswordCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Timeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Timeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Timeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs>
{
    int32_t WINRT_CALL get_AttemptCount(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttemptCount, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AttemptCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Credentials(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Credentials, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynCredentials));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynCredentials>(this->shim().Credentials());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerUniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerUniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PeerUniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedUserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedUserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RequestedUserName());
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
struct produce<D, Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs>
{
    int32_t WINRT_CALL get_AuthenticationMechanism(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationMechanism, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynAuthenticationMechanism>(this->shim().AuthenticationMechanism());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerUniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerUniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PeerUniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().PeerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerCertificateErrorSeverity, WINRT_WRAP(Windows::Networking::Sockets::SocketSslErrorSeverity));
            *value = detach_from<Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().PeerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().PeerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerIntermediateCertificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerIntermediateCertificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().PeerIntermediateCertificates());
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
struct produce<D, Windows::Devices::AllJoyn::IAllJoynMessageInfo> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynMessageInfo>
{
    int32_t WINRT_CALL get_SenderUniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SenderUniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SenderUniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>
{
    int32_t WINRT_CALL Create(void* senderUniqueName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynMessageInfo), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynMessageInfo>(this->shim().Create(*reinterpret_cast<hstring const*>(&senderUniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynProducer> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynProducer>
{
    int32_t WINRT_CALL SetBusObject(void* busObject) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBusObject, WINRT_WRAP(void), Windows::Devices::AllJoyn::AllJoynBusObject const&);
            this->shim().SetBusObject(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynBusObject const*>(&busObject));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs>
{
    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>
{
    int32_t WINRT_CALL Create(int32_t status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs), int32_t);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs>(this->shim().Create(status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynServiceInfo> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynServiceInfo>
{
    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ObjectPath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ObjectPath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ObjectPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionPort(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionPort, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().SessionPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>
{
    int32_t WINRT_CALL Create(void* uniqueName, void* objectPath, uint16_t sessionPort, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynServiceInfo), hstring const&, hstring const&, uint16_t);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynServiceInfo>(this->shim().Create(*reinterpret_cast<hstring const*>(&uniqueName), *reinterpret_cast<hstring const*>(&objectPath), sessionPort));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs>
{
    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>
{
    int32_t WINRT_CALL Create(void* uniqueName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs>(this->shim().Create(*reinterpret_cast<hstring const*>(&uniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynServiceInfo>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynServiceInfo>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSession> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSession>
{
    int32_t WINRT_CALL get_Id(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveMemberAsync(void* uniqueName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveMemberAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<int32_t>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().RemoveMemberAsync(*reinterpret_cast<hstring const*>(&uniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MemberAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemberAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MemberAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MemberAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MemberAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MemberAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MemberRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemberRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MemberRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MemberRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MemberRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MemberRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Lost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Lost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::AllJoyn::AllJoynSession, Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Lost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Lost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Lost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSession));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>
{
    int32_t WINRT_CALL Create(void* session, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs), Windows::Devices::AllJoyn::AllJoynSession const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs>(this->shim().Create(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynSession const*>(&session)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::Devices::AllJoyn::AllJoynSessionLostReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSessionLostReason));
            *value = detach_from<Windows::Devices::AllJoyn::AllJoynSessionLostReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>
{
    int32_t WINRT_CALL Create(Windows::Devices::AllJoyn::AllJoynSessionLostReason reason, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs), Windows::Devices::AllJoyn::AllJoynSessionLostReason const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs>(this->shim().Create(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynSessionLostReason const*>(&reason)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs>
{
    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>
{
    int32_t WINRT_CALL Create(void* uniqueName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs>(this->shim().Create(*reinterpret_cast<hstring const*>(&uniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs>
{
    int32_t WINRT_CALL get_UniqueName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UniqueName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UniqueName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>
{
    int32_t WINRT_CALL Create(void* uniqueName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs), hstring const&);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs>(this->shim().Create(*reinterpret_cast<hstring const*>(&uniqueName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynSessionStatics> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynSessionStatics>
{
    int32_t WINRT_CALL GetFromServiceInfoAsync(void* serviceInfo, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFromServiceInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession>), Windows::Devices::AllJoyn::AllJoynServiceInfo const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession>>(this->shim().GetFromServiceInfoAsync(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynServiceInfo const*>(&serviceInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFromServiceInfoAndBusAttachmentAsync(void* serviceInfo, void* busAttachment, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFromServiceInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession>), Windows::Devices::AllJoyn::AllJoynServiceInfo const, Windows::Devices::AllJoyn::AllJoynBusAttachment const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession>>(this->shim().GetFromServiceInfoAsync(*reinterpret_cast<Windows::Devices::AllJoyn::AllJoynServiceInfo const*>(&serviceInfo), *reinterpret_cast<Windows::Devices::AllJoyn::AllJoynBusAttachment const*>(&busAttachment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynStatusStatics> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynStatusStatics>
{
    int32_t WINRT_CALL get_Ok(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ok, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Ok());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Fail(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fail, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Fail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OperationTimedOut(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperationTimedOut, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().OperationTimedOut());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherEndClosed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherEndClosed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().OtherEndClosed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionRefused(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionRefused, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ConnectionRefused());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationFailed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationFailed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AuthenticationFailed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationRejectedByUser(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationRejectedByUser, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AuthenticationRejectedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SslConnectFailed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SslConnectFailed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SslConnectFailed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SslIdentityVerificationFailed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SslIdentityVerificationFailed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SslIdentityVerificationFailed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientSecurity(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientSecurity, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InsufficientSecurity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument1(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument1, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument2(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument2, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument3(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument3, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument4(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument4, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument4());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument5(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument5, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument5());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument6(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument6, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument6());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument7(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument7, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument7());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidArgument8(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidArgument8, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InvalidArgument8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs>
{
    int32_t WINRT_CALL get_Status(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory> : produce_base<D, Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>
{
    int32_t WINRT_CALL Create(int32_t status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs), int32_t);
            *result = detach_from<Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs>(this->shim().Create(status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::AllJoyn {

inline Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> AllJoynAboutDataView::GetDataBySessionPortAsync(param::hstring const& uniqueName, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort)
{
    return impl::call_factory<AllJoynAboutDataView, Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>([&](auto&& f) { return f.GetDataBySessionPortAsync(uniqueName, busAttachment, sessionPort); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynAboutDataView> AllJoynAboutDataView::GetDataBySessionPortAsync(param::hstring const& uniqueName, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment, uint16_t sessionPort, Windows::Globalization::Language const& language)
{
    return impl::call_factory<AllJoynAboutDataView, Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics>([&](auto&& f) { return f.GetDataBySessionPortAsync(uniqueName, busAttachment, sessionPort, language); });
}

inline AllJoynAcceptSessionJoinerEventArgs::AllJoynAcceptSessionJoinerEventArgs(param::hstring const& uniqueName, uint16_t sessionPort, Windows::Devices::AllJoyn::AllJoynTrafficType const& trafficType, uint8_t proximity, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner const& acceptSessionJoiner) :
    AllJoynAcceptSessionJoinerEventArgs(impl::call_factory<AllJoynAcceptSessionJoinerEventArgs, Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory>([&](auto&& f) { return f.Create(uniqueName, sessionPort, trafficType, proximity, acceptSessionJoiner); }))
{}

inline AllJoynBusAttachment::AllJoynBusAttachment() :
    AllJoynBusAttachment(impl::call_factory<AllJoynBusAttachment>([](auto&& f) { return f.template ActivateInstance<AllJoynBusAttachment>(); }))
{}

inline AllJoynBusAttachment::AllJoynBusAttachment(param::hstring const& connectionSpecification) :
    AllJoynBusAttachment(impl::call_factory<AllJoynBusAttachment, Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory>([&](auto&& f) { return f.Create(connectionSpecification); }))
{}

inline Windows::Devices::AllJoyn::AllJoynBusAttachment AllJoynBusAttachment::GetDefault()
{
    return impl::call_factory<AllJoynBusAttachment, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Enumeration::DeviceWatcher AllJoynBusAttachment::GetWatcher(param::iterable<hstring> const& requiredInterfaces)
{
    return impl::call_factory<AllJoynBusAttachment, Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics>([&](auto&& f) { return f.GetWatcher(requiredInterfaces); });
}

inline AllJoynBusObject::AllJoynBusObject() :
    AllJoynBusObject(impl::call_factory<AllJoynBusObject>([](auto&& f) { return f.template ActivateInstance<AllJoynBusObject>(); }))
{}

inline AllJoynBusObject::AllJoynBusObject(param::hstring const& objectPath) :
    AllJoynBusObject(impl::call_factory<AllJoynBusObject, Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>([&](auto&& f) { return f.Create(objectPath); }))
{}

inline AllJoynBusObject::AllJoynBusObject(param::hstring const& objectPath, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment) :
    AllJoynBusObject(impl::call_factory<AllJoynBusObject, Windows::Devices::AllJoyn::IAllJoynBusObjectFactory>([&](auto&& f) { return f.CreateWithBusAttachment(objectPath, busAttachment); }))
{}

inline AllJoynBusObjectStoppedEventArgs::AllJoynBusObjectStoppedEventArgs(int32_t status) :
    AllJoynBusObjectStoppedEventArgs(impl::call_factory<AllJoynBusObjectStoppedEventArgs, Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory>([&](auto&& f) { return f.Create(status); }))
{}

inline AllJoynMessageInfo::AllJoynMessageInfo(param::hstring const& senderUniqueName) :
    AllJoynMessageInfo(impl::call_factory<AllJoynMessageInfo, Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory>([&](auto&& f) { return f.Create(senderUniqueName); }))
{}

inline AllJoynProducerStoppedEventArgs::AllJoynProducerStoppedEventArgs(int32_t status) :
    AllJoynProducerStoppedEventArgs(impl::call_factory<AllJoynProducerStoppedEventArgs, Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory>([&](auto&& f) { return f.Create(status); }))
{}

inline AllJoynServiceInfo::AllJoynServiceInfo(param::hstring const& uniqueName, param::hstring const& objectPath, uint16_t sessionPort) :
    AllJoynServiceInfo(impl::call_factory<AllJoynServiceInfo, Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory>([&](auto&& f) { return f.Create(uniqueName, objectPath, sessionPort); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynServiceInfo> AllJoynServiceInfo::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<AllJoynServiceInfo, Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline AllJoynServiceInfoRemovedEventArgs::AllJoynServiceInfoRemovedEventArgs(param::hstring const& uniqueName) :
    AllJoynServiceInfoRemovedEventArgs(impl::call_factory<AllJoynServiceInfoRemovedEventArgs, Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory>([&](auto&& f) { return f.Create(uniqueName); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> AllJoynSession::GetFromServiceInfoAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo)
{
    return impl::call_factory<AllJoynSession, Windows::Devices::AllJoyn::IAllJoynSessionStatics>([&](auto&& f) { return f.GetFromServiceInfoAsync(serviceInfo); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::AllJoyn::AllJoynSession> AllJoynSession::GetFromServiceInfoAsync(Windows::Devices::AllJoyn::AllJoynServiceInfo const& serviceInfo, Windows::Devices::AllJoyn::AllJoynBusAttachment const& busAttachment)
{
    return impl::call_factory<AllJoynSession, Windows::Devices::AllJoyn::IAllJoynSessionStatics>([&](auto&& f) { return f.GetFromServiceInfoAsync(serviceInfo, busAttachment); });
}

inline AllJoynSessionJoinedEventArgs::AllJoynSessionJoinedEventArgs(Windows::Devices::AllJoyn::AllJoynSession const& session) :
    AllJoynSessionJoinedEventArgs(impl::call_factory<AllJoynSessionJoinedEventArgs, Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory>([&](auto&& f) { return f.Create(session); }))
{}

inline AllJoynSessionLostEventArgs::AllJoynSessionLostEventArgs(Windows::Devices::AllJoyn::AllJoynSessionLostReason const& reason) :
    AllJoynSessionLostEventArgs(impl::call_factory<AllJoynSessionLostEventArgs, Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory>([&](auto&& f) { return f.Create(reason); }))
{}

inline AllJoynSessionMemberAddedEventArgs::AllJoynSessionMemberAddedEventArgs(param::hstring const& uniqueName) :
    AllJoynSessionMemberAddedEventArgs(impl::call_factory<AllJoynSessionMemberAddedEventArgs, Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory>([&](auto&& f) { return f.Create(uniqueName); }))
{}

inline AllJoynSessionMemberRemovedEventArgs::AllJoynSessionMemberRemovedEventArgs(param::hstring const& uniqueName) :
    AllJoynSessionMemberRemovedEventArgs(impl::call_factory<AllJoynSessionMemberRemovedEventArgs, Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory>([&](auto&& f) { return f.Create(uniqueName); }))
{}

inline int32_t AllJoynStatus::Ok()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.Ok(); });
}

inline int32_t AllJoynStatus::Fail()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.Fail(); });
}

inline int32_t AllJoynStatus::OperationTimedOut()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.OperationTimedOut(); });
}

inline int32_t AllJoynStatus::OtherEndClosed()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.OtherEndClosed(); });
}

inline int32_t AllJoynStatus::ConnectionRefused()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.ConnectionRefused(); });
}

inline int32_t AllJoynStatus::AuthenticationFailed()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.AuthenticationFailed(); });
}

inline int32_t AllJoynStatus::AuthenticationRejectedByUser()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.AuthenticationRejectedByUser(); });
}

inline int32_t AllJoynStatus::SslConnectFailed()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.SslConnectFailed(); });
}

inline int32_t AllJoynStatus::SslIdentityVerificationFailed()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.SslIdentityVerificationFailed(); });
}

inline int32_t AllJoynStatus::InsufficientSecurity()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InsufficientSecurity(); });
}

inline int32_t AllJoynStatus::InvalidArgument1()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument1(); });
}

inline int32_t AllJoynStatus::InvalidArgument2()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument2(); });
}

inline int32_t AllJoynStatus::InvalidArgument3()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument3(); });
}

inline int32_t AllJoynStatus::InvalidArgument4()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument4(); });
}

inline int32_t AllJoynStatus::InvalidArgument5()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument5(); });
}

inline int32_t AllJoynStatus::InvalidArgument6()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument6(); });
}

inline int32_t AllJoynStatus::InvalidArgument7()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument7(); });
}

inline int32_t AllJoynStatus::InvalidArgument8()
{
    return impl::call_factory<AllJoynStatus, Windows::Devices::AllJoyn::IAllJoynStatusStatics>([&](auto&& f) { return f.InvalidArgument8(); });
}

inline AllJoynWatcherStoppedEventArgs::AllJoynWatcherStoppedEventArgs(int32_t status) :
    AllJoynWatcherStoppedEventArgs(impl::call_factory<AllJoynWatcherStoppedEventArgs, Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory>([&](auto&& f) { return f.Create(status); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAboutData> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataView> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAboutDataViewStatics> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoiner> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAcceptSessionJoinerEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynAuthenticationCompleteEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachment2> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusAttachmentStatics> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusObject> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynBusObjectStoppedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynCredentials> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynCredentialsVerificationRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfo> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynMessageInfoFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynProducer> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynProducer> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynProducerStoppedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfo> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoRemovedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynServiceInfoStatics> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSession> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSession> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionJoinedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionLostEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberAddedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionMemberRemovedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynSessionStatics> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynStatusStatics> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::IAllJoynWatcherStoppedEventArgsFactory> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynAboutData> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynAboutData> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynAboutDataView> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynAcceptSessionJoinerEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynAuthenticationCompleteEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachment> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynBusAttachmentStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynBusObject> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynBusObject> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynBusObjectStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynCredentials> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynCredentials> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynCredentialsVerificationRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynMessageInfo> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynProducerStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfo> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynServiceInfoRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynSession> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynSession> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynSessionJoinedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynSessionLostEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberAddedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynSessionMemberRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynStatus> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynStatus> {};
template<> struct hash<winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::AllJoyn::AllJoynWatcherStoppedEventArgs> {};

}
