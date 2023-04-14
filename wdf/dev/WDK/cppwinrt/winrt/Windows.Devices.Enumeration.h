// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Enumeration::DeviceAccessStatus consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs<D>::Status() const
{
    Windows::Devices::Enumeration::DeviceAccessStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformation)->add_AccessChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged_revoker consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessChanged_revoker>(this, AccessChanged(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::AccessChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformation)->remove_AccessChanged(get_abi(cookie)));
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessStatus consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>::CurrentStatus() const
{
    Windows::Devices::Enumeration::DeviceAccessStatus status{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformation)->get_CurrentStatus(put_abi(status)));
    return status;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromId(param::hstring const& deviceId) const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromId(get_abi(deviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromDeviceClassId(winrt::guid const& deviceClassId) const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromDeviceClassId(get_abi(deviceClassId), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>::CreateFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceAccessInformationStatics)->CreateFromDeviceClass(get_abi(deviceClass), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceConnectionChangeTriggerDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Enumeration_IDeviceDisconnectButtonClickedEventArgs<D>::Device() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs)->get_Device(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_Name(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformation<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_IsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformation<D>::IsDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_IsDefault(&value));
    return value;
}

template <typename D> Windows::Devices::Enumeration::EnclosureLocation consume_Windows_Devices_Enumeration_IDeviceInformation<D>::EnclosureLocation() const
{
    Windows::Devices::Enumeration::EnclosureLocation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_EnclosureLocation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceInformation<D>::Update(Windows::Devices::Enumeration::DeviceInformationUpdate const& updateInfo) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->Update(get_abi(updateInfo)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> consume_Windows_Devices_Enumeration_IDeviceInformation<D>::GetThumbnailAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->GetThumbnailAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> consume_Windows_Devices_Enumeration_IDeviceInformation<D>::GetGlyphThumbnailAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation)->GetGlyphThumbnailAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformationKind consume_Windows_Devices_Enumeration_IDeviceInformation2<D>::Kind() const
{
    Windows::Devices::Enumeration::DeviceInformationKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation2)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformationPairing consume_Windows_Devices_Enumeration_IDeviceInformation2<D>::Pairing() const
{
    Windows::Devices::Enumeration::DeviceInformationPairing value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformation2)->get_Pairing(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairAsync(get_abi(pairingKindsSupported), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairWithProtectionLevelAsync(get_abi(pairingKindsSupported), get_abi(minProtectionLevel), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->PairWithProtectionLevelAndSettingsAsync(get_abi(pairingKindsSupported), get_abi(minProtectionLevel), get_abi(devicePairingSettings), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->add_PairingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested_revoker consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PairingRequested_revoker>(this, PairingRequested(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>::PairingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationCustomPairing)->remove_PairingRequested(get_abi(token)));
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::IsPaired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing)->get_IsPaired(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::CanPair() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing)->get_CanPair(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::PairAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing)->PairAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>::PairAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing)->PairWithProtectionLevelAsync(get_abi(minProtectionLevel), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Enumeration::DevicePairingProtectionLevel consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::ProtectionLevel() const
{
    Windows::Devices::Enumeration::DevicePairingProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing2)->get_ProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformationCustomPairing consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::Custom() const
{
    Windows::Devices::Enumeration::DeviceInformationCustomPairing value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing2)->get_Custom(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::PairAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing2)->PairWithProtectionLevelAndSettingsAsync(get_abi(minProtectionLevel), get_abi(devicePairingSettings), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceUnpairingResult> consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>::UnpairAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceUnpairingResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairing2)->UnpairAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics<D>::TryRegisterForAllInboundPairingRequests(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairingStatics)->TryRegisterForAllInboundPairingRequests(get_abi(pairingKindsSupported), &result));
    return result;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics2<D>::TryRegisterForAllInboundPairingRequestsWithProtectionLevel(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationPairingStatics2)->TryRegisterForAllInboundPairingRequestsWithProtectionLevel(get_abi(pairingKindsSupported), get_abi(minProtectionLevel), &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateFromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateFromIdAsync(get_abi(deviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateFromIdAsyncAdditionalProperties(get_abi(deviceId), get_abi(additionalProperties), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncDeviceClass(get_abi(deviceClass), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(param::hstring const& aqsFilter) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncAqsFilter(get_abi(aqsFilter), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->FindAllAsyncAqsFilterAndAdditionalProperties(get_abi(aqsFilter), get_abi(additionalProperties), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher() const
{
    Windows::Devices::Enumeration::DeviceWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcher(put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
{
    Windows::Devices::Enumeration::DeviceWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherDeviceClass(get_abi(deviceClass), put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(param::hstring const& aqsFilter) const
{
    Windows::Devices::Enumeration::DeviceWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherAqsFilter(get_abi(aqsFilter), put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties) const
{
    Windows::Devices::Enumeration::DeviceWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics)->CreateWatcherAqsFilterAndAdditionalProperties(get_abi(aqsFilter), get_abi(additionalProperties), put_abi(watcher)));
    return watcher;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::GetAqsFilterFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const
{
    hstring aqsFilter{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics2)->GetAqsFilterFromDeviceClass(get_abi(deviceClass), put_abi(aqsFilter)));
    return aqsFilter;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics2)->CreateFromIdAsyncWithKindAndAdditionalProperties(get_abi(deviceId), get_abi(additionalProperties), get_abi(kind), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics2)->FindAllAsyncWithKindAqsFilterAndAdditionalProperties(get_abi(aqsFilter), get_abi(additionalProperties), get_abi(kind), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcher consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const
{
    Windows::Devices::Enumeration::DeviceWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationStatics2)->CreateWatcherWithKindAqsFilterAndAdditionalProperties(get_abi(aqsFilter), get_abi(additionalProperties), get_abi(kind), put_abi(watcher)));
    return watcher;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDeviceInformationUpdate<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationUpdate)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Enumeration_IDeviceInformationUpdate<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationUpdate)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformationKind consume_Windows_Devices_Enumeration_IDeviceInformationUpdate2<D>::Kind() const
{
    Windows::Devices::Enumeration::DeviceInformationKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceInformationUpdate2)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DevicePairingKinds consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::PairingKind() const
{
    Windows::Devices::Enumeration::DevicePairingKinds value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_PairingKind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Pin() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->get_Pin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Accept() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->Accept());
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::Accept(param::hstring const& pin) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->AcceptWithPin(get_abi(pin)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs2<D>::AcceptWithPasswordCredential(Windows::Security::Credentials::PasswordCredential const& passwordCredential) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2)->AcceptWithPasswordCredential(get_abi(passwordCredential)));
}

template <typename D> Windows::Devices::Enumeration::DevicePairingResultStatus consume_Windows_Devices_Enumeration_IDevicePairingResult<D>::Status() const
{
    Windows::Devices::Enumeration::DevicePairingResultStatus status{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingResult)->get_Status(put_abi(status)));
    return status;
}

template <typename D> Windows::Devices::Enumeration::DevicePairingProtectionLevel consume_Windows_Devices_Enumeration_IDevicePairingResult<D>::ProtectionLevelUsed() const
{
    Windows::Devices::Enumeration::DevicePairingProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePairingResult)->get_ProtectionLevelUsed(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DevicePickerFilter consume_Windows_Devices_Enumeration_IDevicePicker<D>::Filter() const
{
    Windows::Devices::Enumeration::DevicePickerFilter filter{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->get_Filter(put_abi(filter)));
    return filter;
}

template <typename D> Windows::Devices::Enumeration::DevicePickerAppearance consume_Windows_Devices_Enumeration_IDevicePicker<D>::Appearance() const
{
    Windows::Devices::Enumeration::DevicePickerAppearance value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->get_Appearance(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Enumeration_IDevicePicker<D>::RequestedProperties() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->get_RequestedProperties(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->add_DeviceSelected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DeviceSelected_revoker>(this, DeviceSelected(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::DeviceSelected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->remove_DeviceSelected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->add_DisconnectButtonClicked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DisconnectButtonClicked_revoker>(this, DisconnectButtonClicked(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::DisconnectButtonClicked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->remove_DisconnectButtonClicked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->add_DevicePickerDismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed_revoker consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DevicePickerDismissed_revoker>(this, DevicePickerDismissed(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::DevicePickerDismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->remove_DevicePickerDismissed(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::Show(Windows::Foundation::Rect const& selection) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->Show(get_abi(selection)));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& placement) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->ShowWithPlacement(get_abi(selection), get_abi(placement)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> consume_Windows_Devices_Enumeration_IDevicePicker<D>::PickSingleDeviceAsync(Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->PickSingleDeviceAsync(get_abi(selection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> consume_Windows_Devices_Enumeration_IDevicePicker<D>::PickSingleDeviceAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& placement) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->PickSingleDeviceAsyncWithPlacement(get_abi(selection), get_abi(placement), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::Hide() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->Hide());
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePicker<D>::SetDisplayStatus(Windows::Devices::Enumeration::DeviceInformation const& device, param::hstring const& status, Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePicker)->SetDisplayStatus(get_abi(device), get_abi(status), get_abi(options)));
}

template <typename D> hstring consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_Title(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::ForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::ForegroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::AccentColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_AccentColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::AccentColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_AccentColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedForegroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedForegroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedBackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedBackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedBackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedAccentColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->get_SelectedAccentColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>::SelectedAccentColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerAppearance)->put_SelectedAccentColor(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Enumeration::DeviceClass> consume_Windows_Devices_Enumeration_IDevicePickerFilter<D>::SupportedDeviceClasses() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Enumeration::DeviceClass> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerFilter)->get_SupportedDeviceClasses(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Devices_Enumeration_IDevicePickerFilter<D>::SupportedDeviceSelectors() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDevicePickerFilter)->get_SupportedDeviceSelectors(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Enumeration_IDeviceSelectedEventArgs<D>::SelectedDevice() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceSelectedEventArgs)->get_SelectedDevice(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceUnpairingResultStatus consume_Windows_Devices_Enumeration_IDeviceUnpairingResult<D>::Status() const
{
    Windows::Devices::Enumeration::DeviceUnpairingResultStatus status{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceUnpairingResult)->get_Status(put_abi(status)));
    return status;
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped_revoker consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcherStatus consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Status() const
{
    Windows::Devices::Enumeration::DeviceWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->Start());
}

template <typename D> void consume_Windows_Devices_Enumeration_IDeviceWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher)->Stop());
}

template <typename D> Windows::ApplicationModel::Background::DeviceWatcherTrigger consume_Windows_Devices_Enumeration_IDeviceWatcher2<D>::GetBackgroundTrigger(param::iterable<Windows::Devices::Enumeration::DeviceWatcherEventKind> const& requestedEventKinds) const
{
    Windows::ApplicationModel::Background::DeviceWatcherTrigger trigger{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcher2)->GetBackgroundTrigger(get_abi(requestedEventKinds), put_abi(trigger)));
    return trigger;
}

template <typename D> Windows::Devices::Enumeration::DeviceWatcherEventKind consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::Kind() const
{
    Windows::Devices::Enumeration::DeviceWatcherEventKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformationUpdate consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>::DeviceInformationUpdate() const
{
    Windows::Devices::Enumeration::DeviceInformationUpdate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcherEvent)->get_DeviceInformationUpdate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceWatcherEvent> consume_Windows_Devices_Enumeration_IDeviceWatcherTriggerDetails<D>::DeviceWatcherEvents() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceWatcherEvent> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails)->get_DeviceWatcherEvents(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::InDock() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IEnclosureLocation)->get_InDock(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::InLid() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IEnclosureLocation)->get_InLid(&value));
    return value;
}

template <typename D> Windows::Devices::Enumeration::Panel consume_Windows_Devices_Enumeration_IEnclosureLocation<D>::Panel() const
{
    Windows::Devices::Enumeration::Panel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IEnclosureLocation)->get_Panel(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Enumeration_IEnclosureLocation2<D>::RotationAngleInDegreesClockwise() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Enumeration::IEnclosureLocation2)->get_RotationAngleInDegreesClockwise(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> : produce_base<D, Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceAccessStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessStatus));
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> : produce_base<D, Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>
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
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceAccessInformation> : produce_base<D, Windows::Devices::Enumeration::IDeviceAccessInformation>
{
    int32_t WINRT_CALL add_AccessChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AccessChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_CurrentStatus(Windows::Devices::Enumeration::DeviceAccessStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentStatus, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessStatus));
            *status = detach_from<Windows::Devices::Enumeration::DeviceAccessStatus>(this->shim().CurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceAccessInformationStatics> : produce_base<D, Windows::Devices::Enumeration::IDeviceAccessInformationStatics>
{
    int32_t WINRT_CALL CreateFromId(void* deviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromId, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessInformation), hstring const&);
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromDeviceClassId(winrt::guid deviceClassId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDeviceClassId, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessInformation), winrt::guid const&);
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromDeviceClassId(*reinterpret_cast<winrt::guid const*>(&deviceClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDeviceClass, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessInformation), Windows::Devices::Enumeration::DeviceClass const&);
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().CreateFromDeviceClass(*reinterpret_cast<Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> : produce_base<D, Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>
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
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> : produce_base<D, Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformation> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformation>
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

    int32_t WINRT_CALL get_IsDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnclosureLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnclosureLocation, WINRT_WRAP(Windows::Devices::Enumeration::EnclosureLocation));
            *value = detach_from<Windows::Devices::Enumeration::EnclosureLocation>(this->shim().EnclosureLocation());
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

    int32_t WINRT_CALL Update(void* updateInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void), Windows::Devices::Enumeration::DeviceInformationUpdate const&);
            this->shim().Update(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformationUpdate const*>(&updateInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail>>(this->shim().GetThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGlyphThumbnailAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGlyphThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail>>(this->shim().GetGlyphThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformation2> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformation2>
{
    int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceInformationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformationKind));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pairing(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pairing, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformationPairing));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformationPairing>(this->shim().Pairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationCustomPairing> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationCustomPairing>
{
    int32_t WINRT_CALL PairAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>), Windows::Devices::Enumeration::DevicePairingKinds const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PairWithProtectionLevelAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>), Windows::Devices::Enumeration::DevicePairingKinds const, Windows::Devices::Enumeration::DevicePairingProtectionLevel const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PairWithProtectionLevelAndSettingsAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void* devicePairingSettings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>), Windows::Devices::Enumeration::DevicePairingKinds const, Windows::Devices::Enumeration::DevicePairingProtectionLevel const, Windows::Devices::Enumeration::IDevicePairingSettings const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel), *reinterpret_cast<Windows::Devices::Enumeration::IDevicePairingSettings const*>(&devicePairingSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PairingRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PairingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PairingRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PairingRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PairingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationPairing> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationPairing>
{
    int32_t WINRT_CALL get_IsPaired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPaired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPaired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanPair(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPair, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanPair());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PairAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PairWithProtectionLevelAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>), Windows::Devices::Enumeration::DevicePairingProtectionLevel const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationPairing2> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationPairing2>
{
    int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Enumeration::DevicePairingProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(Windows::Devices::Enumeration::DevicePairingProtectionLevel));
            *value = detach_from<Windows::Devices::Enumeration::DevicePairingProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Custom(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Custom, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformationCustomPairing));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformationCustomPairing>(this->shim().Custom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PairWithProtectionLevelAndSettingsAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void* devicePairingSettings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>), Windows::Devices::Enumeration::DevicePairingProtectionLevel const, Windows::Devices::Enumeration::IDevicePairingSettings const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult>>(this->shim().PairAsync(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel), *reinterpret_cast<Windows::Devices::Enumeration::IDevicePairingSettings const*>(&devicePairingSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnpairAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnpairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceUnpairingResult>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceUnpairingResult>>(this->shim().UnpairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationPairingStatics> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationPairingStatics>
{
    int32_t WINRT_CALL TryRegisterForAllInboundPairingRequests(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRegisterForAllInboundPairingRequests, WINRT_WRAP(bool), Windows::Devices::Enumeration::DevicePairingKinds const&);
            *result = detach_from<bool>(this->shim().TryRegisterForAllInboundPairingRequests(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>
{
    int32_t WINRT_CALL TryRegisterForAllInboundPairingRequestsWithProtectionLevel(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRegisterForAllInboundPairingRequestsWithProtectionLevel, WINRT_WRAP(bool), Windows::Devices::Enumeration::DevicePairingKinds const&, Windows::Devices::Enumeration::DevicePairingProtectionLevel const&);
            *result = detach_from<bool>(this->shim().TryRegisterForAllInboundPairingRequestsWithProtectionLevel(*reinterpret_cast<Windows::Devices::Enumeration::DevicePairingKinds const*>(&pairingKindsSupported), *reinterpret_cast<Windows::Devices::Enumeration::DevicePairingProtectionLevel const*>(&minProtectionLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationStatics> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationStatics>
{
    int32_t WINRT_CALL CreateFromIdAsync(void* deviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIdAsyncAdditionalProperties(void* deviceId, void* additionalProperties, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>), Windows::Devices::Enumeration::DeviceClass const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncAqsFilter(void* aqsFilter, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
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
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher));
            *watcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher), Windows::Devices::Enumeration::DeviceClass const&);
            *watcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherAqsFilter(void* aqsFilter, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher), hstring const&);
            *watcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *watcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationStatics2> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationStatics2>
{
    int32_t WINRT_CALL GetAqsFilterFromDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** aqsFilter) noexcept final
    {
        try
        {
            *aqsFilter = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAqsFilterFromDeviceClass, WINRT_WRAP(hstring), Windows::Devices::Enumeration::DeviceClass const&);
            *aqsFilter = detach_from<hstring>(this->shim().GetAqsFilterFromDeviceClass(*reinterpret_cast<Windows::Devices::Enumeration::DeviceClass const*>(&deviceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIdAsyncWithKindAndAdditionalProperties(void* deviceId, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Devices::Enumeration::DeviceInformationKind const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>>(this->shim().CreateFromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Devices::Enumeration::DeviceInformationKind const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcherWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcher), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&, Windows::Devices::Enumeration::DeviceInformationKind const&);
            *watcher = detach_from<Windows::Devices::Enumeration::DeviceWatcher>(this->shim().CreateWatcher(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&additionalProperties), *reinterpret_cast<Windows::Devices::Enumeration::DeviceInformationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationUpdate> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationUpdate>
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
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceInformationUpdate2> : produce_base<D, Windows::Devices::Enumeration::IDeviceInformationUpdate2>
{
    int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceInformationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformationKind));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> : produce_base<D, Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>
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

    int32_t WINRT_CALL get_PairingKind(Windows::Devices::Enumeration::DevicePairingKinds* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PairingKind, WINRT_WRAP(Windows::Devices::Enumeration::DevicePairingKinds));
            *value = detach_from<Windows::Devices::Enumeration::DevicePairingKinds>(this->shim().PairingKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pin(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pin, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pin());
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

    int32_t WINRT_CALL AcceptWithPin(void* pin) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accept, WINRT_WRAP(void), hstring const&);
            this->shim().Accept(*reinterpret_cast<hstring const*>(&pin));
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
struct produce<D, Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> : produce_base<D, Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>
{
    int32_t WINRT_CALL AcceptWithPasswordCredential(void* passwordCredential) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptWithPasswordCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().AcceptWithPasswordCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePairingResult> : produce_base<D, Windows::Devices::Enumeration::IDevicePairingResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DevicePairingResultStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Enumeration::DevicePairingResultStatus));
            *status = detach_from<Windows::Devices::Enumeration::DevicePairingResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionLevelUsed(Windows::Devices::Enumeration::DevicePairingProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevelUsed, WINRT_WRAP(Windows::Devices::Enumeration::DevicePairingProtectionLevel));
            *value = detach_from<Windows::Devices::Enumeration::DevicePairingProtectionLevel>(this->shim().ProtectionLevelUsed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePairingSettings> : produce_base<D, Windows::Devices::Enumeration::IDevicePairingSettings>
{};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePicker> : produce_base<D, Windows::Devices::Enumeration::IDevicePicker>
{
    int32_t WINRT_CALL get_Filter(void** filter) noexcept final
    {
        try
        {
            *filter = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Filter, WINRT_WRAP(Windows::Devices::Enumeration::DevicePickerFilter));
            *filter = detach_from<Windows::Devices::Enumeration::DevicePickerFilter>(this->shim().Filter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Appearance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Appearance, WINRT_WRAP(Windows::Devices::Enumeration::DevicePickerAppearance));
            *value = detach_from<Windows::Devices::Enumeration::DevicePickerAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedProperties, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().RequestedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DeviceSelected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceSelected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DeviceSelected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeviceSelected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeviceSelected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeviceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectButtonClicked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisconnectButtonClicked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisconnectButtonClicked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisconnectButtonClicked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisconnectButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DevicePickerDismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DevicePickerDismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DevicePickerDismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DevicePickerDismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DevicePickerDismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DevicePickerDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement placement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&placement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickSingleDeviceAsync(Windows::Foundation::Rect selection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>), Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>>(this->shim().PickSingleDeviceAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickSingleDeviceAsyncWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement placement, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleDeviceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>), Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation>>(this->shim().PickSingleDeviceAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&placement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Hide() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hide, WINRT_WRAP(void));
            this->shim().Hide();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDisplayStatus(void* device, void* status, Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDisplayStatus, WINRT_WRAP(void), Windows::Devices::Enumeration::DeviceInformation const&, hstring const&, Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const&);
            this->shim().SetDisplayStatus(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&device), *reinterpret_cast<hstring const*>(&status), *reinterpret_cast<Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePickerAppearance> : produce_base<D, Windows::Devices::Enumeration::IDevicePickerAppearance>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().ForegroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccentColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccentColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().AccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccentColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccentColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().AccentColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedForegroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForegroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SelectedForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedForegroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedForegroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().SelectedForegroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SelectedBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedBackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedBackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().SelectedBackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedAccentColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedAccentColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SelectedAccentColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedAccentColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedAccentColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().SelectedAccentColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDevicePickerFilter> : produce_base<D, Windows::Devices::Enumeration::IDevicePickerFilter>
{
    int32_t WINRT_CALL get_SupportedDeviceClasses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDeviceClasses, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Enumeration::DeviceClass>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Enumeration::DeviceClass>>(this->shim().SupportedDeviceClasses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedDeviceSelectors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDeviceSelectors, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SupportedDeviceSelectors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceSelectedEventArgs> : produce_base<D, Windows::Devices::Enumeration::IDeviceSelectedEventArgs>
{
    int32_t WINRT_CALL get_SelectedDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedDevice, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().SelectedDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceUnpairingResult> : produce_base<D, Windows::Devices::Enumeration::IDeviceUnpairingResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceUnpairingResultStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Enumeration::DeviceUnpairingResultStatus));
            *status = detach_from<Windows::Devices::Enumeration::DeviceUnpairingResultStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceWatcher> : produce_base<D, Windows::Devices::Enumeration::IDeviceWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcherStatus));
            *status = detach_from<Windows::Devices::Enumeration::DeviceWatcherStatus>(this->shim().Status());
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
struct produce<D, Windows::Devices::Enumeration::IDeviceWatcher2> : produce_base<D, Windows::Devices::Enumeration::IDeviceWatcher2>
{
    int32_t WINRT_CALL GetBackgroundTrigger(void* requestedEventKinds, void** trigger) noexcept final
    {
        try
        {
            *trigger = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBackgroundTrigger, WINRT_WRAP(Windows::ApplicationModel::Background::DeviceWatcherTrigger), Windows::Foundation::Collections::IIterable<Windows::Devices::Enumeration::DeviceWatcherEventKind> const&);
            *trigger = detach_from<Windows::ApplicationModel::Background::DeviceWatcherTrigger>(this->shim().GetBackgroundTrigger(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Enumeration::DeviceWatcherEventKind> const*>(&requestedEventKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceWatcherEvent> : produce_base<D, Windows::Devices::Enumeration::IDeviceWatcherEvent>
{
    int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceWatcherEventKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Devices::Enumeration::DeviceWatcherEventKind));
            *value = detach_from<Windows::Devices::Enumeration::DeviceWatcherEventKind>(this->shim().Kind());
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
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInformationUpdate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformationUpdate, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformationUpdate));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformationUpdate>(this->shim().DeviceInformationUpdate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> : produce_base<D, Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>
{
    int32_t WINRT_CALL get_DeviceWatcherEvents(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceWatcherEvents, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceWatcherEvent>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceWatcherEvent>>(this->shim().DeviceWatcherEvents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IEnclosureLocation> : produce_base<D, Windows::Devices::Enumeration::IEnclosureLocation>
{
    int32_t WINRT_CALL get_InDock(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InDock, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InDock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InLid(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InLid, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InLid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Panel(Windows::Devices::Enumeration::Panel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Panel, WINRT_WRAP(Windows::Devices::Enumeration::Panel));
            *value = detach_from<Windows::Devices::Enumeration::Panel>(this->shim().Panel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Enumeration::IEnclosureLocation2> : produce_base<D, Windows::Devices::Enumeration::IEnclosureLocation2>
{
    int32_t WINRT_CALL get_RotationAngleInDegreesClockwise(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngleInDegreesClockwise, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RotationAngleInDegreesClockwise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

inline Windows::Devices::Enumeration::DeviceAccessInformation DeviceAccessInformation::CreateFromId(param::hstring const& deviceId)
{
    return impl::call_factory<DeviceAccessInformation, Windows::Devices::Enumeration::IDeviceAccessInformationStatics>([&](auto&& f) { return f.CreateFromId(deviceId); });
}

inline Windows::Devices::Enumeration::DeviceAccessInformation DeviceAccessInformation::CreateFromDeviceClassId(winrt::guid const& deviceClassId)
{
    return impl::call_factory<DeviceAccessInformation, Windows::Devices::Enumeration::IDeviceAccessInformationStatics>([&](auto&& f) { return f.CreateFromDeviceClassId(deviceClassId); });
}

inline Windows::Devices::Enumeration::DeviceAccessInformation DeviceAccessInformation::CreateFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass)
{
    return impl::call_factory<DeviceAccessInformation, Windows::Devices::Enumeration::IDeviceAccessInformationStatics>([&](auto&& f) { return f.CreateFromDeviceClass(deviceClass); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateFromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateFromIdAsync(deviceId, additionalProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> DeviceInformation::FindAllAsync()
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> DeviceInformation::FindAllAsync(Windows::Devices::Enumeration::DeviceClass const& deviceClass)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.FindAllAsync(deviceClass); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> DeviceInformation::FindAllAsync(param::hstring const& aqsFilter)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.FindAllAsync(aqsFilter); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> DeviceInformation::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.FindAllAsync(aqsFilter, additionalProperties); });
}

inline Windows::Devices::Enumeration::DeviceWatcher DeviceInformation::CreateWatcher()
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateWatcher(); });
}

inline Windows::Devices::Enumeration::DeviceWatcher DeviceInformation::CreateWatcher(Windows::Devices::Enumeration::DeviceClass const& deviceClass)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateWatcher(deviceClass); });
}

inline Windows::Devices::Enumeration::DeviceWatcher DeviceInformation::CreateWatcher(param::hstring const& aqsFilter)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateWatcher(aqsFilter); });
}

inline Windows::Devices::Enumeration::DeviceWatcher DeviceInformation::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics>([&](auto&& f) { return f.CreateWatcher(aqsFilter, additionalProperties); });
}

inline hstring DeviceInformation::GetAqsFilterFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics2>([&](auto&& f) { return f.GetAqsFilterFromDeviceClass(deviceClass); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> DeviceInformation::CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics2>([&](auto&& f) { return f.CreateFromIdAsync(deviceId, additionalProperties, kind); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> DeviceInformation::FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics2>([&](auto&& f) { return f.FindAllAsync(aqsFilter, additionalProperties, kind); });
}

inline Windows::Devices::Enumeration::DeviceWatcher DeviceInformation::CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind)
{
    return impl::call_factory<DeviceInformation, Windows::Devices::Enumeration::IDeviceInformationStatics2>([&](auto&& f) { return f.CreateWatcher(aqsFilter, additionalProperties, kind); });
}

inline bool DeviceInformationPairing::TryRegisterForAllInboundPairingRequests(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported)
{
    return impl::call_factory<DeviceInformationPairing, Windows::Devices::Enumeration::IDeviceInformationPairingStatics>([&](auto&& f) { return f.TryRegisterForAllInboundPairingRequests(pairingKindsSupported); });
}

inline bool DeviceInformationPairing::TryRegisterForAllInboundPairingRequestsWithProtectionLevel(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel)
{
    return impl::call_factory<DeviceInformationPairing, Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>([&](auto&& f) { return f.TryRegisterForAllInboundPairingRequestsWithProtectionLevel(pairingKindsSupported, minProtectionLevel); });
}

inline DevicePicker::DevicePicker() :
    DevicePicker(impl::call_factory<DevicePicker>([](auto&& f) { return f.template ActivateInstance<DevicePicker>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceAccessInformation> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceAccessInformationStatics> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformation> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformation2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformation2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationCustomPairing> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationPairing2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationStatics2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceInformationUpdate2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingResult> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePairingResult> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePairingSettings> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePairingSettings> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePicker> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePicker> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePickerAppearance> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePickerAppearance> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDevicePickerFilter> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceUnpairingResult> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceWatcher> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcher2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceWatcher2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceWatcherEvent> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IEnclosureLocation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IEnclosureLocation> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::IEnclosureLocation2> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::IEnclosureLocation2> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceAccessInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceAccessInformation> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceInformation> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationCollection> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceInformationCollection> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceInformationCustomPairing> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationPairing> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceInformationPairing> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceInformationUpdate> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePairingResult> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DevicePairingResult> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePicker> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DevicePicker> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePickerAppearance> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DevicePickerAppearance> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DevicePickerFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DevicePickerFilter> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceThumbnail> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceThumbnail> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceUnpairingResult> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceWatcher> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceWatcherEvent> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::DeviceWatcherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::DeviceWatcherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Enumeration::EnclosureLocation> : winrt::impl::hash_base<winrt::Windows::Devices::Enumeration::EnclosureLocation> {};

}
