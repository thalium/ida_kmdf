// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Advertisement.2.h"
#include "winrt/Windows.Devices.Bluetooth.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::Flags() const
{
    Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_Flags(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::Flags(optional<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->put_Flags(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::LocalName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_LocalName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::LocalName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->put_LocalName(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<winrt::guid> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::ServiceUuids() const
{
    Windows::Foundation::Collections::IVector<winrt::guid> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_ServiceUuids(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::ManufacturerData() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_ManufacturerData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::DataSections() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->get_DataSections(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::GetManufacturerDataByCompanyId(uint16_t companyId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> dataList{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->GetManufacturerDataByCompanyId(companyId, put_abi(dataList)));
    return dataList;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisement<D>::GetSectionsByType(uint8_t type) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> sectionList{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement)->GetSectionsByType(type, put_abi(sectionList)));
    return sectionList;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::DataType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_DataType(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::DataType(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_DataType(value));
}

template <typename D> int16_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Offset() const
{
    int16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_Offset(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Offset(int16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_Offset(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePattern<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern)->put_Data(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementBytePatternFactory<D>::Create(uint8_t dataType, int16_t offset, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory)->Create(dataType, offset, get_abi(data), put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::DataType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->get_DataType(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::DataType(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->put_DataType(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSection<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection)->put_Data(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataSectionFactory<D>::Create(uint8_t dataType, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory)->Create(dataType, get_abi(data), put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::Flags() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_Flags(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService16BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService16BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService16BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService16BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService32BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService32BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService32BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService32BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::IncompleteService128BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_IncompleteService128BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteService128BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteService128BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ShortenedLocalName() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ShortenedLocalName(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::CompleteLocalName() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_CompleteLocalName(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::TxPowerLevel() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_TxPowerLevel(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::SlaveConnectionIntervalRange() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_SlaveConnectionIntervalRange(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation16BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation16BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation32BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation32BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceSolicitation128BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceSolicitation128BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData16BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData16BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData32BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData32BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ServiceData128BitUuids() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ServiceData128BitUuids(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::PublicTargetAddress() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_PublicTargetAddress(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::RandomTargetAddress() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_RandomTargetAddress(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::Appearance() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_Appearance(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::AdvertisingInterval() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_AdvertisingInterval(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementDataTypesStatics<D>::ManufacturerSpecificData() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics)->get_ManufacturerSpecificData(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::Advertisement() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->get_Advertisement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::Advertisement(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->put_Advertisement(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementFilter<D>::BytePatterns() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter)->get_BytePatterns(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Status() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Advertisement() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->get_Advertisement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->Start());
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->add_StatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisher<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher)->remove_StatusChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherFactory<D>::Create(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement) const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory)->Create(get_abi(advertisement), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs<D>::Status() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementPublisherStatusChangedEventArgs<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> int16_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::RawSignalStrengthInDBm() const
{
    int16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_RawSignalStrengthInDBm(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::BluetoothAddress() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_BluetoothAddress(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::AdvertisementType() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_AdvertisementType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementReceivedEventArgs<D>::Advertisement() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs)->get_Advertisement(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MinSamplingInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MinSamplingInterval(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MaxSamplingInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MaxSamplingInterval(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MinOutOfRangeTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MinOutOfRangeTimeout(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::MaxOutOfRangeTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_MaxOutOfRangeTimeout(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Status() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::ScanningMode() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_ScanningMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::ScanningMode(Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_ScanningMode(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::SignalStrengthFilter() const
{
    Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_SignalStrengthFilter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::SignalStrengthFilter(Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_SignalStrengthFilter(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::AdvertisementFilter() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->get_AdvertisementFilter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::AdvertisementFilter(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->put_AdvertisementFilter(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->Start());
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->add_Received(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Received_revoker>(this, Received(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Received(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->remove_Received(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped_revoker consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherFactory<D>::Create(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter) const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory)->Create(get_abi(advertisementFilter), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEAdvertisementWatcherStoppedEventArgs<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::CompanyId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->get_CompanyId(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::CompanyId(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->put_CompanyId(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerData<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData)->put_Data(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData consume_Windows_Devices_Bluetooth_Advertisement_IBluetoothLEManufacturerDataFactory<D>::Create(uint16_t companyId, Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory)->Create(companyId, get_abi(data), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement>
{
    int32_t WINRT_CALL get_Flags(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flags, WINRT_WRAP(Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags>>(this->shim().Flags());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Flags(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flags, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const&);
            this->shim().Flags(*reinterpret_cast<Windows::Foundation::IReference<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFlags> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalName, WINRT_WRAP(void), hstring const&);
            this->shim().LocalName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceUuids(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceUuids, WINRT_WRAP(Windows::Foundation::Collections::IVector<winrt::guid>));
            *value = detach_from<Windows::Foundation::Collections::IVector<winrt::guid>>(this->shim().ServiceUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerData, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>>(this->shim().ManufacturerData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataSections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataSections, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>>(this->shim().DataSections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetManufacturerDataByCompanyId(uint16_t companyId, void** dataList) noexcept final
    {
        try
        {
            *dataList = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetManufacturerDataByCompanyId, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>), uint16_t);
            *dataList = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>>(this->shim().GetManufacturerDataByCompanyId(companyId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSectionsByType(uint8_t type, void** sectionList) noexcept final
    {
        try
        {
            *sectionList = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSectionsByType, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>), uint8_t);
            *sectionList = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>>(this->shim().GetSectionsByType(type));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern>
{
    int32_t WINRT_CALL get_DataType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataType(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(void), uint8_t);
            this->shim().DataType(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(int16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(int16_t));
            *value = detach_from<int16_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(int16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), int16_t);
            this->shim().Offset(value);
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

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>
{
    int32_t WINRT_CALL Create(uint8_t dataType, int16_t offset, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern), uint8_t, int16_t, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>(this->shim().Create(dataType, offset, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection>
{
    int32_t WINRT_CALL get_DataType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataType(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(void), uint8_t);
            this->shim().DataType(value);
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

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>
{
    int32_t WINRT_CALL Create(uint8_t dataType, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection), uint8_t, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection>(this->shim().Create(dataType, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>
{
    int32_t WINRT_CALL get_Flags(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flags, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Flags());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncompleteService16BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncompleteService16BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().IncompleteService16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompleteService16BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteService16BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().CompleteService16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncompleteService32BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncompleteService32BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().IncompleteService32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompleteService32BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteService32BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().CompleteService32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncompleteService128BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncompleteService128BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().IncompleteService128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompleteService128BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteService128BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().CompleteService128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShortenedLocalName(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortenedLocalName, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ShortenedLocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompleteLocalName(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteLocalName, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().CompleteLocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TxPowerLevel(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TxPowerLevel, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().TxPowerLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SlaveConnectionIntervalRange(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlaveConnectionIntervalRange, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SlaveConnectionIntervalRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceSolicitation16BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceSolicitation16BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceSolicitation32BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceSolicitation32BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceSolicitation128BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceSolicitation128BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceSolicitation128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceData16BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceData16BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceData16BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceData32BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceData32BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceData32BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceData128BitUuids(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceData128BitUuids, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ServiceData128BitUuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicTargetAddress(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicTargetAddress, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().PublicTargetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RandomTargetAddress(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RandomTargetAddress, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().RandomTargetAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Appearance(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Appearance, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisingInterval(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisingInterval, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().AdvertisingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerSpecificData(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerSpecificData, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ManufacturerSpecificData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter>
{
    int32_t WINRT_CALL get_Advertisement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Advertisement, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Advertisement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Advertisement, WINRT_WRAP(void), Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const&);
            this->shim().Advertisement(*reinterpret_cast<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytePatterns(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytePatterns, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern>>(this->shim().BytePatterns());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Advertisement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Advertisement, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
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

    int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>
{
    int32_t WINRT_CALL Create(void* advertisement, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher), Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const&);
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher>(this->shim().Create(*reinterpret_cast<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const*>(&advertisement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothError));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs>
{
    int32_t WINRT_CALL get_RawSignalStrengthInDBm(int16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawSignalStrengthInDBm, WINRT_WRAP(int16_t));
            *value = detach_from<int16_t>(this->shim().RawSignalStrengthInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BluetoothAddress(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothAddress, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisementType(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementType, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementType>(this->shim().AdvertisementType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Advertisement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Advertisement, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement>(this->shim().Advertisement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher>
{
    int32_t WINRT_CALL get_MinSamplingInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSamplingInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MinSamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSamplingInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSamplingInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaxSamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinOutOfRangeTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinOutOfRangeTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MinOutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxOutOfRangeTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxOutOfRangeTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaxOutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanningMode(Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanningMode, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode>(this->shim().ScanningMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScanningMode(Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanningMode, WINRT_WRAP(void), Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const&);
            this->shim().ScanningMode(*reinterpret_cast<Windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalStrengthFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalStrengthFilter, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter>(this->shim().SignalStrengthFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignalStrengthFilter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalStrengthFilter, WINRT_WRAP(void), Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const&);
            this->shim().SignalStrengthFilter(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisementFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementFilter, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter>(this->shim().AdvertisementFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AdvertisementFilter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementFilter, WINRT_WRAP(void), Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const&);
            this->shim().AdvertisementFilter(*reinterpret_cast<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const*>(&value));
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

    int32_t WINRT_CALL add_Received(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Received, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Received(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Received(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Received, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Received(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>
{
    int32_t WINRT_CALL Create(void* advertisementFilter, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher), Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const&);
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher>(this->shim().Create(*reinterpret_cast<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const*>(&advertisementFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs>
{
    int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothError));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData>
{
    int32_t WINRT_CALL get_CompanyId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CompanyId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompanyId(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyId, WINRT_WRAP(void), uint16_t);
            this->shim().CompanyId(value);
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

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> : produce_base<D, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>
{
    int32_t WINRT_CALL Create(uint16_t companyId, void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData), uint16_t, Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData>(this->shim().Create(companyId, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Advertisement {

inline BluetoothLEAdvertisement::BluetoothLEAdvertisement() :
    BluetoothLEAdvertisement(impl::call_factory<BluetoothLEAdvertisement>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisement>(); }))
{}

inline BluetoothLEAdvertisementBytePattern::BluetoothLEAdvertisementBytePattern() :
    BluetoothLEAdvertisementBytePattern(impl::call_factory<BluetoothLEAdvertisementBytePattern>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisementBytePattern>(); }))
{}

inline BluetoothLEAdvertisementBytePattern::BluetoothLEAdvertisementBytePattern(uint8_t dataType, int16_t offset, Windows::Storage::Streams::IBuffer const& data) :
    BluetoothLEAdvertisementBytePattern(impl::call_factory<BluetoothLEAdvertisementBytePattern, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory>([&](auto&& f) { return f.Create(dataType, offset, data); }))
{}

inline BluetoothLEAdvertisementDataSection::BluetoothLEAdvertisementDataSection() :
    BluetoothLEAdvertisementDataSection(impl::call_factory<BluetoothLEAdvertisementDataSection>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisementDataSection>(); }))
{}

inline BluetoothLEAdvertisementDataSection::BluetoothLEAdvertisementDataSection(uint8_t dataType, Windows::Storage::Streams::IBuffer const& data) :
    BluetoothLEAdvertisementDataSection(impl::call_factory<BluetoothLEAdvertisementDataSection, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory>([&](auto&& f) { return f.Create(dataType, data); }))
{}

inline uint8_t BluetoothLEAdvertisementDataTypes::Flags()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.Flags(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::IncompleteService16BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.IncompleteService16BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::CompleteService16BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.CompleteService16BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::IncompleteService32BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.IncompleteService32BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::CompleteService32BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.CompleteService32BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::IncompleteService128BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.IncompleteService128BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::CompleteService128BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.CompleteService128BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ShortenedLocalName()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ShortenedLocalName(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::CompleteLocalName()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.CompleteLocalName(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::TxPowerLevel()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.TxPowerLevel(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::SlaveConnectionIntervalRange()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.SlaveConnectionIntervalRange(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceSolicitation16BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceSolicitation16BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceSolicitation32BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceSolicitation32BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceSolicitation128BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceSolicitation128BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceData16BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceData16BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceData32BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceData32BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ServiceData128BitUuids()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ServiceData128BitUuids(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::PublicTargetAddress()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.PublicTargetAddress(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::RandomTargetAddress()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.RandomTargetAddress(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::Appearance()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.Appearance(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::AdvertisingInterval()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.AdvertisingInterval(); });
}

inline uint8_t BluetoothLEAdvertisementDataTypes::ManufacturerSpecificData()
{
    return impl::call_factory<BluetoothLEAdvertisementDataTypes, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics>([&](auto&& f) { return f.ManufacturerSpecificData(); });
}

inline BluetoothLEAdvertisementFilter::BluetoothLEAdvertisementFilter() :
    BluetoothLEAdvertisementFilter(impl::call_factory<BluetoothLEAdvertisementFilter>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisementFilter>(); }))
{}

inline BluetoothLEAdvertisementPublisher::BluetoothLEAdvertisementPublisher() :
    BluetoothLEAdvertisementPublisher(impl::call_factory<BluetoothLEAdvertisementPublisher>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisementPublisher>(); }))
{}

inline BluetoothLEAdvertisementPublisher::BluetoothLEAdvertisementPublisher(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement const& advertisement) :
    BluetoothLEAdvertisementPublisher(impl::call_factory<BluetoothLEAdvertisementPublisher, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory>([&](auto&& f) { return f.Create(advertisement); }))
{}

inline BluetoothLEAdvertisementWatcher::BluetoothLEAdvertisementWatcher() :
    BluetoothLEAdvertisementWatcher(impl::call_factory<BluetoothLEAdvertisementWatcher>([](auto&& f) { return f.template ActivateInstance<BluetoothLEAdvertisementWatcher>(); }))
{}

inline BluetoothLEAdvertisementWatcher::BluetoothLEAdvertisementWatcher(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter const& advertisementFilter) :
    BluetoothLEAdvertisementWatcher(impl::call_factory<BluetoothLEAdvertisementWatcher, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory>([&](auto&& f) { return f.Create(advertisementFilter); }))
{}

inline BluetoothLEManufacturerData::BluetoothLEManufacturerData() :
    BluetoothLEManufacturerData(impl::call_factory<BluetoothLEManufacturerData>([](auto&& f) { return f.template ActivateInstance<BluetoothLEManufacturerData>(); }))
{}

inline BluetoothLEManufacturerData::BluetoothLEManufacturerData(uint16_t companyId, Windows::Storage::Streams::IBuffer const& data) :
    BluetoothLEManufacturerData(impl::call_factory<BluetoothLEManufacturerData, Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory>([&](auto&& f) { return f.Create(companyId, data); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisement> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePattern> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementBytePatternFactory> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSection> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataSectionFactory> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementDataTypesStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementFilter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisher> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherFactory> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementPublisherStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcher> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherFactory> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEAdvertisementWatcherStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerData> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::IBluetoothLEManufacturerDataFactory> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisement> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementBytePattern> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataSection> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataTypes> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementDataTypes> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementFilter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisher> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcher> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementWatcherStoppedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData> {};

}
