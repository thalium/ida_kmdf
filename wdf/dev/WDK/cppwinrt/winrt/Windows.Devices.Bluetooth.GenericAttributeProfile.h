// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.2.h"
#include "winrt/Windows.Devices.Bluetooth.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::GetDescriptors(winrt::guid const& descriptorUuid) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->GetDescriptors(get_abi(descriptorUuid), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::CharacteristicProperties() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_CharacteristicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_ProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->put_ProtectionLevel(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::UserDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_UserDescription(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::AttributeHandle() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_AttributeHandle(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::PresentationFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->get_PresentationFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ReadValueAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->ReadValueAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ReadValueAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->ReadValueWithCacheModeAsync(get_abi(cacheMode), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::WriteValueAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->WriteValueAsync(get_abi(value), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::WriteValueAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const& writeOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->WriteValueWithOptionAsync(get_abi(value), get_abi(writeOption), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ReadClientCharacteristicConfigurationDescriptorAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->ReadClientCharacteristicConfigurationDescriptorAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::WriteClientCharacteristicConfigurationDescriptorAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const& clientCharacteristicConfigurationDescriptorValue) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->WriteClientCharacteristicConfigurationDescriptorAsync(get_abi(clientCharacteristicConfigurationDescriptorValue), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ValueChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const& valueChangedHandler) const
{
    winrt::event_token valueChangedEventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->add_ValueChanged(get_abi(valueChangedHandler), put_abi(valueChangedEventCookie)));
    return valueChangedEventCookie;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ValueChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ValueChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const& valueChangedHandler) const
{
    return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(valueChangedHandler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>::ValueChanged(winrt::event_token const& valueChangedEventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic)->remove_ValueChanged(get_abi(valueChangedEventCookie)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic2<D>::Service() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2)->get_Service(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic2<D>::GetAllDescriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> descriptors{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2)->GetAllDescriptors(put_abi(descriptors)));
    return descriptors;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::GetDescriptorsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->GetDescriptorsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::GetDescriptorsAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->GetDescriptorsWithCacheModeAsync(get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::GetDescriptorsForUuidAsync(winrt::guid const& descriptorUuid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->GetDescriptorsForUuidAsync(get_abi(descriptorUuid), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::GetDescriptorsForUuidAsync(winrt::guid const& descriptorUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->GetDescriptorsForUuidWithCacheModeAsync(get_abi(descriptorUuid), get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->WriteValueWithResultAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const& writeOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->WriteValueWithResultAndOptionAsync(get_abi(value), get_abi(writeOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>::WriteClientCharacteristicConfigurationDescriptorWithResultAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const& clientCharacteristicConfigurationDescriptorValue) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3)->WriteClientCharacteristicConfigurationDescriptorWithResultAsync(get_abi(clientCharacteristicConfigurationDescriptorValue), put_abi(operation)));
    return operation;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicStatics<D>::ConvertShortIdToUuid(uint16_t shortId) const
{
    winrt::guid characteristicUuid{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics)->ConvertShortIdToUuid(shortId, put_abi(characteristicUuid)));
    return characteristicUuid;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::BatteryLevel() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_BatteryLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::BloodPressureFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_BloodPressureFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::BloodPressureMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_BloodPressureMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::BodySensorLocation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_BodySensorLocation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::CscFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_CscFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::CscMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_CscMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::GlucoseFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_GlucoseFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::GlucoseMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_GlucoseMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::GlucoseMeasurementContext() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_GlucoseMeasurementContext(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::HeartRateControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_HeartRateControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::HeartRateMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_HeartRateMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::IntermediateCuffPressure() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_IntermediateCuffPressure(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::IntermediateTemperature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_IntermediateTemperature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::MeasurementInterval() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_MeasurementInterval(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::RecordAccessControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_RecordAccessControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::RscFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_RscFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::RscMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_RscMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::SCControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_SCControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::SensorLocation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_SensorLocation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::TemperatureMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_TemperatureMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>::TemperatureType() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics)->get_TemperatureType(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::AlertCategoryId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_AlertCategoryId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::AlertCategoryIdBitMask() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_AlertCategoryIdBitMask(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::AlertLevel() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_AlertLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::AlertNotificationControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_AlertNotificationControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::AlertStatus() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_AlertStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GapAppearance() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GapAppearance(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::BootKeyboardInputReport() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_BootKeyboardInputReport(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::BootKeyboardOutputReport() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_BootKeyboardOutputReport(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::BootMouseInputReport() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_BootMouseInputReport(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::CurrentTime() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_CurrentTime(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::CyclingPowerControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_CyclingPowerControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::CyclingPowerFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_CyclingPowerFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::CyclingPowerMeasurement() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_CyclingPowerMeasurement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::CyclingPowerVector() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_CyclingPowerVector(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::DateTime() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_DateTime(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::DayDateTime() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_DayDateTime(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::DayOfWeek() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_DayOfWeek(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GapDeviceName() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GapDeviceName(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::DstOffset() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_DstOffset(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ExactTime256() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ExactTime256(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::FirmwareRevisionString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_FirmwareRevisionString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::HardwareRevisionString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_HardwareRevisionString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::HidControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_HidControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::HidInformation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_HidInformation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::Ieee1107320601RegulatoryCertificationDataList() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_Ieee1107320601RegulatoryCertificationDataList(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::LnControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_LnControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::LnFeature() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_LnFeature(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::LocalTimeInformation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_LocalTimeInformation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::LocationAndSpeed() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_LocationAndSpeed(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ManufacturerNameString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ManufacturerNameString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ModelNumberString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ModelNumberString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::Navigation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_Navigation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::NewAlert() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_NewAlert(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GapPeripheralPreferredConnectionParameters() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GapPeripheralPreferredConnectionParameters(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GapPeripheralPrivacyFlag() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GapPeripheralPrivacyFlag(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::PnpId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_PnpId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::PositionQuality() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_PositionQuality(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ProtocolMode() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ProtocolMode(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GapReconnectionAddress() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GapReconnectionAddress(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ReferenceTimeInformation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ReferenceTimeInformation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::Report() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_Report(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ReportMap() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ReportMap(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::RingerControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_RingerControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::RingerSetting() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_RingerSetting(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ScanIntervalWindow() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ScanIntervalWindow(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::ScanRefresh() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_ScanRefresh(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::SerialNumberString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_SerialNumberString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::GattServiceChanged() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_GattServiceChanged(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::SoftwareRevisionString() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_SoftwareRevisionString(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::SupportedNewAlertCategory() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_SupportedNewAlertCategory(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::SupportUnreadAlertCategory() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_SupportUnreadAlertCategory(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::SystemId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_SystemId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeAccuracy() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeAccuracy(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeSource() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeSource(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeUpdateControlPoint() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeUpdateControlPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeUpdateState() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeUpdateState(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeWithDst() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeWithDst(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TimeZone() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TimeZone(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::TxPowerLevel() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_TxPowerLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>::UnreadAlertStatus() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2)->get_UnreadAlertStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicsResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicsResult<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicsResult<D>::Characteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult)->get_Characteristics(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult<D>::SubscribedClient() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult)->get_SubscribedClient(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult2<D>::BytesSent() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2)->get_BytesSent(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::ProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->get_ProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->put_ProtectionLevel(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::AttributeHandle() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->get_AttributeHandle(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::ReadValueAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->ReadValueAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::ReadValueAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->ReadValueWithCacheModeAsync(get_abi(cacheMode), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>::WriteValueAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor)->WriteValueAsync(get_abi(value), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor2<D>::WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2)->WriteValueWithResultAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorStatics<D>::ConvertShortIdToUuid(uint16_t shortId) const
{
    winrt::guid descriptorUuid{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics)->ConvertShortIdToUuid(shortId, put_abi(descriptorUuid)));
    return descriptorUuid;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::CharacteristicAggregateFormat() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_CharacteristicAggregateFormat(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::CharacteristicExtendedProperties() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_CharacteristicExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::CharacteristicPresentationFormat() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_CharacteristicPresentationFormat(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::CharacteristicUserDescription() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_CharacteristicUserDescription(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::ClientCharacteristicConfiguration() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_ClientCharacteristicConfiguration(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>::ServerCharacteristicConfiguration() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics)->get_ServerCharacteristicConfiguration(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorsResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorsResult<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorsResult<D>::Descriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult)->get_Descriptors(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>::GetCharacteristics(winrt::guid const& characteristicUuid) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService)->GetCharacteristics(get_abi(characteristicUuid), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>::GetIncludedServices(winrt::guid const& serviceUuid) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService)->GetIncludedServices(get_abi(serviceUuid), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>::AttributeHandle() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService)->get_AttributeHandle(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothLEDevice consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2<D>::Device() const
{
    Windows::Devices::Bluetooth::BluetoothLEDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2<D>::ParentServices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2)->get_ParentServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2<D>::GetAllCharacteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> characteristics{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2)->GetAllCharacteristics(put_abi(characteristics)));
    return characteristics;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2<D>::GetAllIncludedServices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> includedServices{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2)->GetAllIncludedServices(put_abi(includedServices)));
    return includedServices;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::DeviceAccessInformation() const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->get_DeviceAccessInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::Session() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::SharingMode() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->RequestAccessAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::OpenAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->OpenAsync(get_abi(sharingMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetCharacteristicsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetCharacteristicsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetCharacteristicsAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetCharacteristicsWithCacheModeAsync(get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetCharacteristicsForUuidAsync(winrt::guid const& characteristicUuid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetCharacteristicsForUuidAsync(get_abi(characteristicUuid), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetCharacteristicsForUuidAsync(winrt::guid const& characteristicUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetCharacteristicsForUuidWithCacheModeAsync(get_abi(characteristicUuid), get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetIncludedServicesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetIncludedServicesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetIncludedServicesAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetIncludedServicesWithCacheModeAsync(get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetIncludedServicesForUuidAsync(winrt::guid const& serviceUuid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetIncludedServicesForUuidAsync(get_abi(serviceUuid), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>::GetIncludedServicesForUuidAsync(winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3)->GetIncludedServicesForUuidWithCacheModeAsync(get_abi(serviceUuid), get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics)->FromIdAsync(get_abi(deviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics<D>::GetDeviceSelectorFromUuid(winrt::guid const& serviceUuid) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics)->GetDeviceSelectorFromUuid(get_abi(serviceUuid), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics<D>::GetDeviceSelectorFromShortId(uint16_t serviceShortId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics)->GetDeviceSelectorFromShortId(serviceShortId, put_abi(selector)));
    return selector;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics<D>::ConvertShortIdToUuid(uint16_t shortId) const
{
    winrt::guid serviceUuid{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics)->ConvertShortIdToUuid(shortId, put_abi(serviceUuid)));
    return serviceUuid;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>::FromIdAsync(param::hstring const& deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2)->FromIdWithSharingModeAsync(get_abi(deviceId), get_abi(sharingMode), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceId(get_abi(bluetoothDeviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceIdWithCacheMode(get_abi(bluetoothDeviceId), get_abi(cacheMode), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceIdAndUuid(get_abi(bluetoothDeviceId), get_abi(serviceUuid), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceIdAndUuidWithCacheMode(get_abi(bluetoothDeviceId), get_abi(serviceUuid), get_abi(cacheMode), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServicesResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServicesResult<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServicesResult<D>::Services() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult)->get_Services(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::StaticValue() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_StaticValue(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::CharacteristicProperties() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_CharacteristicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::ReadProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_ReadProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::WriteProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_WriteProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::CreateDescriptorAsync(winrt::guid const& descriptorUuid, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters const& parameters) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->CreateDescriptorAsync(get_abi(descriptorUuid), get_abi(parameters), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::Descriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_Descriptors(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::UserDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_UserDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::PresentationFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_PresentationFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::SubscribedClients() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->get_SubscribedClients(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::SubscribedClientsChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->add_SubscribedClientsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::SubscribedClientsChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::SubscribedClientsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SubscribedClientsChanged_revoker>(this, SubscribedClientsChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::SubscribedClientsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->remove_SubscribedClientsChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::ReadRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->add_ReadRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::ReadRequested_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::ReadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadRequested_revoker>(this, ReadRequested(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::ReadRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->remove_ReadRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::WriteRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->add_WriteRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::WriteRequested_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::WriteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WriteRequested_revoker>(this, WriteRequested(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::WriteRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->remove_WriteRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::NotifyValueAsync(Windows::Storage::Streams::IBuffer const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->NotifyValueAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>::NotifyValueAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient const& subscribedClient) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic)->NotifyValueForSubscribedClientAsync(get_abi(value), get_abi(subscribedClient), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::StaticValue(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->put_StaticValue(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::StaticValue() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_StaticValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->put_CharacteristicProperties(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::CharacteristicProperties() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_CharacteristicProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->put_ReadProtectionLevel(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::ReadProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_ReadProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->put_WriteProtectionLevel(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::WriteProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_WriteProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::UserDescription(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->put_UserDescription(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::UserDescription() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_UserDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>::PresentationFormats() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters)->get_PresentationFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicResult<D>::Characteristic() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult)->get_Characteristic(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicResult<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult)->get_Error(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::StaticValue() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->get_StaticValue(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::ReadProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->get_ReadProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::WriteProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->get_WriteProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::ReadRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->add_ReadRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::ReadRequested_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::ReadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadRequested_revoker>(this, ReadRequested(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::ReadRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->remove_ReadRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::WriteRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->add_WriteRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::WriteRequested_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::WriteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WriteRequested_revoker>(this, WriteRequested(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>::WriteRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor)->remove_WriteRequested(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::StaticValue(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->put_StaticValue(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::StaticValue() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->get_StaticValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->put_ReadProtectionLevel(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::ReadProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->get_ReadProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->put_WriteProtectionLevel(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>::WriteProtectionLevel() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters)->get_WriteProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorResult<D>::Descriptor() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult)->get_Descriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorResult<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult)->get_Error(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalService<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalService<D>::CreateCharacteristicAsync(winrt::guid const& characteristicUuid, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters const& parameters) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService)->CreateCharacteristicAsync(get_abi(characteristicUuid), get_abi(parameters), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalService<D>::Characteristics() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService)->get_Characteristics(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>::FormatType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat)->get_FormatType(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>::Exponent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat)->get_Exponent(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>::Unit() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat)->get_Unit(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>::Namespace() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat)->get_Namespace(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>::Description() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat)->get_Description(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics<D>::BluetoothSigAssignedNumbers() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics)->get_BluetoothSigAssignedNumbers(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics2<D>::FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description) const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2)->FromParts(formatType, exponent, unit, namespaceId, description, put_abi(result)));
    return result;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Boolean() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Boolean(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Bit2() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Bit2(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Nibble() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Nibble(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt8() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt8(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt12() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt12(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt16() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt16(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt24() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt24(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt32() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt32(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt48() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt48(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt64() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt64(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::UInt128() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_UInt128(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt8() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt8(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt12() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt12(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt16() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt16(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt24() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt24(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt32() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt32(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt48() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt48(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt64() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt64(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SInt128() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SInt128(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Float32() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Float32(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Float64() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Float64(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::SFloat() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_SFloat(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Float() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Float(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::DUInt16() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_DUInt16(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Utf8() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Utf8(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Utf16() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Utf16(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>::Struct() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics)->get_Struct(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InvalidHandle() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InvalidHandle(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::ReadNotPermitted() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_ReadNotPermitted(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::WriteNotPermitted() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_WriteNotPermitted(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InvalidPdu() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InvalidPdu(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InsufficientAuthentication() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InsufficientAuthentication(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::RequestNotSupported() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_RequestNotSupported(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InvalidOffset() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InvalidOffset(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InsufficientAuthorization() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InsufficientAuthorization(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::PrepareQueueFull() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_PrepareQueueFull(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::AttributeNotFound() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_AttributeNotFound(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::AttributeNotLong() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_AttributeNotLong(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InsufficientEncryptionKeySize() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InsufficientEncryptionKeySize(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InvalidAttributeValueLength() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InvalidAttributeValueLength(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::UnlikelyError() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_UnlikelyError(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InsufficientEncryption() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InsufficientEncryption(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::UnsupportedGroupType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_UnsupportedGroupType(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>::InsufficientResources() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics)->get_InsufficientResources(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult<D>::ClientCharacteristicConfigurationDescriptor() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult)->get_ClientCharacteristicConfigurationDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult2<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::Offset() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->get_Offset(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::Length() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->get_Length(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::State() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::StateChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->remove_StateChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::RespondWithValue(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->RespondWithValue(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>::RespondWithProtocolError(uint8_t protocolError) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest)->RespondWithProtocolError(protocolError));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequestedEventArgs<D>::Session() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequestedEventArgs<D>::GetRequestAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs)->GetRequestAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult<D>::Value() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult2<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction<D>::WriteValue(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const& characteristic, Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction)->WriteValue(get_abi(characteristic), get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction<D>::CommitAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction)->CommitAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction2<D>::CommitWithResultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2)->CommitWithResultAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattRequestStateChangedEventArgs<D>::State() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattRequestStateChangedEventArgs<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::Service() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->get_Service(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::AdvertisementStatus() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->get_AdvertisementStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::AdvertisementStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->add_AdvertisementStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::AdvertisementStatusChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::AdvertisementStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AdvertisementStatusChanged_revoker>(this, AdvertisementStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::AdvertisementStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->remove_AdvertisementStatusChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::StartAdvertising() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->StartAdvertising());
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::StartAdvertising(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters const& parameters) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->StartAdvertisingWithParameters(get_abi(parameters)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>::StopAdvertising() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider)->StopAdvertising());
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisementStatusChangedEventArgs<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisementStatusChangedEventArgs<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters<D>::IsConnectable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters)->put_IsConnectable(value));
}

template <typename D> bool consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters<D>::IsConnectable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters)->get_IsConnectable(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters<D>::IsDiscoverable(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters)->put_IsDiscoverable(value));
}

template <typename D> bool consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters<D>::IsDiscoverable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters)->get_IsDiscoverable(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters2<D>::ServiceData(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2)->put_ServiceData(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters2<D>::ServiceData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2)->get_ServiceData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderResult<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderResult<D>::ServiceProvider() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult)->get_ServiceProvider(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderStatics<D>::CreateAsync(winrt::guid const& serviceUuid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics)->CreateAsync(get_abi(serviceUuid), put_abi(operation)));
    return operation;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::Battery() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_Battery(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::BloodPressure() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_BloodPressure(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::CyclingSpeedAndCadence() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_CyclingSpeedAndCadence(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::GenericAccess() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_GenericAccess(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::GenericAttribute() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_GenericAttribute(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::Glucose() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_Glucose(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::HealthThermometer() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_HealthThermometer(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::HeartRate() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_HeartRate(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>::RunningSpeedAndCadence() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics)->get_RunningSpeedAndCadence(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::AlertNotification() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_AlertNotification(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::CurrentTime() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_CurrentTime(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::CyclingPower() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_CyclingPower(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::DeviceInformation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::HumanInterfaceDevice() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_HumanInterfaceDevice(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::ImmediateAlert() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_ImmediateAlert(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::LinkLoss() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_LinkLoss(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::LocationAndNavigation() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_LocationAndNavigation(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::NextDstChange() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_NextDstChange(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::PhoneAlertStatus() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_PhoneAlertStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::ReferenceTimeUpdate() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_ReferenceTimeUpdate(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::ScanParameters() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_ScanParameters(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>::TxPower() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2)->get_TxPower(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDeviceId consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::DeviceId() const
{
    Windows::Devices::Bluetooth::BluetoothDeviceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::CanMaintainConnection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->get_CanMaintainConnection(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaintainConnection(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->put_MaintainConnection(value));
}

template <typename D> bool consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaintainConnection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->get_MaintainConnection(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaxPduSize() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->get_MaxPduSize(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::SessionStatus() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->get_SessionStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaxPduSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->add_MaxPduSizeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaxPduSizeChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaxPduSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, MaxPduSizeChanged_revoker>(this, MaxPduSizeChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::MaxPduSizeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->remove_MaxPduSizeChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::SessionStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->add_SessionStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::SessionStatusChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::SessionStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionStatusChanged_revoker>(this, SessionStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>::SessionStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession)->remove_SessionStatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatics<D>::FromDeviceIdAsync(Windows::Devices::Bluetooth::BluetoothDeviceId const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics)->FromDeviceIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatusChangedEventArgs<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatusChangedEventArgs<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::Session() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient)->get_Session(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::MaxNotificationSize() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient)->get_MaxNotificationSize(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::MaxNotificationSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient)->add_MaxNotificationSizeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::MaxNotificationSizeChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::MaxNotificationSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, MaxNotificationSizeChanged_revoker>(this, MaxNotificationSizeChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>::MaxNotificationSizeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient)->remove_MaxNotificationSizeChanged(get_abi(token)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattValueChangedEventArgs<D>::CharacteristicValue() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs)->get_CharacteristicValue(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattValueChangedEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime timestamp{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs)->get_Timestamp(put_abi(timestamp)));
    return timestamp;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::Value() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->get_Value(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::Offset() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->get_Offset(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::Option() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->get_Option(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::State() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::StateChanged_revoker consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->remove_StateChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::Respond() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->Respond());
}

template <typename D> void consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>::RespondWithProtocolError(uint8_t protocolError) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest)->RespondWithProtocolError(protocolError));
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequestedEventArgs<D>::Session() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequestedEventArgs<D>::GetRequestAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs)->GetRequestAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteResult<D>::Status() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteResult<D>::ProtocolError() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult)->get_ProtocolError(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>
{
    int32_t WINRT_CALL GetDescriptors(winrt::guid descriptorUuid, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>), winrt::guid const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>>(this->shim().GetDescriptors(*reinterpret_cast<winrt::guid const*>(&descriptorUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicProperties, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties>(this->shim().CharacteristicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().ProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributeHandle, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AttributeHandle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>>(this->shim().PresentationFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadValueAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>>(this->shim().ReadValueAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadValueWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>>(this->shim().ReadValueAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteValueAsync(void* value, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>), Windows::Storage::Streams::IBuffer const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>>(this->shim().WriteValueAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteValueWithOptionAsync(void* value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption writeOption, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>), Windows::Storage::Streams::IBuffer const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>>(this->shim().WriteValueAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const*>(&writeOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadClientCharacteristicConfigurationDescriptorAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadClientCharacteristicConfigurationDescriptorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult>>(this->shim().ReadClientCharacteristicConfigurationDescriptorAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteClientCharacteristicConfigurationDescriptorAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue clientCharacteristicConfigurationDescriptorValue, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteClientCharacteristicConfigurationDescriptorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>), Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>>(this->shim().WriteClientCharacteristicConfigurationDescriptorAsync(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const*>(&clientCharacteristicConfigurationDescriptorValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ValueChanged(void* valueChangedHandler, winrt::event_token* valueChangedEventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const&);
            *valueChangedEventCookie = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const*>(&valueChangedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ValueChanged(winrt::event_token valueChangedEventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&valueChangedEventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2>
{
    int32_t WINRT_CALL get_Service(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Service, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>(this->shim().Service());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllDescriptors(void** descriptors) noexcept final
    {
        try
        {
            *descriptors = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllDescriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>));
            *descriptors = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>>(this->shim().GetAllDescriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>
{
    int32_t WINRT_CALL GetDescriptorsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescriptorsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>>(this->shim().GetDescriptorsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDescriptorsWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescriptorsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>>(this->shim().GetDescriptorsAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDescriptorsForUuidAsync(winrt::guid descriptorUuid, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescriptorsForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>), winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>>(this->shim().GetDescriptorsForUuidAsync(*reinterpret_cast<winrt::guid const*>(&descriptorUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDescriptorsForUuidWithCacheModeAsync(winrt::guid descriptorUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescriptorsForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>), winrt::guid const, Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>>(this->shim().GetDescriptorsForUuidAsync(*reinterpret_cast<winrt::guid const*>(&descriptorUuid), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteValueWithResultAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>>(this->shim().WriteValueWithResultAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteValueWithResultAndOptionAsync(void* value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption writeOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>), Windows::Storage::Streams::IBuffer const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>>(this->shim().WriteValueWithResultAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const*>(&writeOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteClientCharacteristicConfigurationDescriptorWithResultAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue clientCharacteristicConfigurationDescriptorValue, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteClientCharacteristicConfigurationDescriptorWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>), Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>>(this->shim().WriteClientCharacteristicConfigurationDescriptorWithResultAsync(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const*>(&clientCharacteristicConfigurationDescriptorValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>
{
    int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* characteristicUuid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertShortIdToUuid, WINRT_WRAP(winrt::guid), uint16_t);
            *characteristicUuid = detach_from<winrt::guid>(this->shim().ConvertShortIdToUuid(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>
{
    int32_t WINRT_CALL get_BatteryLevel(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatteryLevel, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BatteryLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressureFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressureFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BloodPressureFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressureMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressureMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BloodPressureMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BodySensorLocation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BodySensorLocation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BodySensorLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CscFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CscFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CscFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CscMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CscMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CscMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlucoseFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlucoseFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GlucoseFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlucoseMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlucoseMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GlucoseMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlucoseMeasurementContext(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlucoseMeasurementContext, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GlucoseMeasurementContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeartRateControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartRateControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HeartRateControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeartRateMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartRateMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HeartRateMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IntermediateCuffPressure(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IntermediateCuffPressure, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().IntermediateCuffPressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IntermediateTemperature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IntermediateTemperature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().IntermediateTemperature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MeasurementInterval(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeasurementInterval, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().MeasurementInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordAccessControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordAccessControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RecordAccessControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RscFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RscFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RscFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RscMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RscMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RscMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SCControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SCControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SCControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SensorLocation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SensorLocation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SensorLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TemperatureMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TemperatureMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TemperatureMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TemperatureType(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TemperatureType, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TemperatureType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>
{
    int32_t WINRT_CALL get_AlertCategoryId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertCategoryId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertCategoryId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlertCategoryIdBitMask(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertCategoryIdBitMask, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertCategoryIdBitMask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlertLevel(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertLevel, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlertNotificationControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertNotificationControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertNotificationControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlertStatus(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertStatus, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GapAppearance(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GapAppearance, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GapAppearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BootKeyboardInputReport(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BootKeyboardInputReport, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BootKeyboardInputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BootKeyboardOutputReport(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BootKeyboardOutputReport, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BootKeyboardOutputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BootMouseInputReport(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BootMouseInputReport, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BootMouseInputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentTime(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentTime, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CurrentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPowerControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPowerControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingPowerControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPowerFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPowerFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingPowerFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPowerMeasurement(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPowerMeasurement, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingPowerMeasurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPowerVector(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPowerVector, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingPowerVector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTime(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTime, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DayDateTime(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayDateTime, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DayDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DayOfWeek(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DayOfWeek, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DayOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GapDeviceName(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GapDeviceName, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GapDeviceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DstOffset(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DstOffset, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DstOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExactTime256(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExactTime256, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ExactTime256());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirmwareRevisionString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirmwareRevisionString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().FirmwareRevisionString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareRevisionString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareRevisionString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HardwareRevisionString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HidControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HidControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HidControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HidInformation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HidInformation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HidInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ieee1107320601RegulatoryCertificationDataList(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ieee1107320601RegulatoryCertificationDataList, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Ieee1107320601RegulatoryCertificationDataList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LnControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LnControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LnControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LnFeature(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LnFeature, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LnFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalTimeInformation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalTimeInformation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LocalTimeInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationAndSpeed(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationAndSpeed, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LocationAndSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManufacturerNameString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManufacturerNameString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ManufacturerNameString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelNumberString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelNumberString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ModelNumberString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Navigation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Navigation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Navigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewAlert(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewAlert, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NewAlert());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GapPeripheralPreferredConnectionParameters(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GapPeripheralPreferredConnectionParameters, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GapPeripheralPreferredConnectionParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GapPeripheralPrivacyFlag(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GapPeripheralPrivacyFlag, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GapPeripheralPrivacyFlag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PnpId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PnpId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PnpId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionQuality(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionQuality, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PositionQuality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolMode(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolMode, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ProtocolMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GapReconnectionAddress(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GapReconnectionAddress, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GapReconnectionAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReferenceTimeInformation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReferenceTimeInformation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ReferenceTimeInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Report(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Report, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Report());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportMap(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportMap, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ReportMap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RingerControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RingerControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RingerControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RingerSetting(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RingerSetting, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RingerSetting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanIntervalWindow(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanIntervalWindow, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ScanIntervalWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanRefresh(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanRefresh, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ScanRefresh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SerialNumberString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialNumberString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SerialNumberString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GattServiceChanged(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GattServiceChanged, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GattServiceChanged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoftwareRevisionString(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareRevisionString, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SoftwareRevisionString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedNewAlertCategory(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedNewAlertCategory, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SupportedNewAlertCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportUnreadAlertCategory(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportUnreadAlertCategory, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SupportUnreadAlertCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeAccuracy(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeAccuracy, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeSource(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeSource, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeUpdateControlPoint(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeUpdateControlPoint, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeUpdateControlPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeUpdateState(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeUpdateState, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeUpdateState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeWithDst(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeWithDst, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeWithDst());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeZone(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeZone, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TimeZone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TxPowerLevel(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TxPowerLevel, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TxPowerLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnreadAlertStatus(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnreadAlertStatus, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().UnreadAlertStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Characteristics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult>
{
    int32_t WINRT_CALL get_SubscribedClient(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscribedClient, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>(this->shim().SubscribedClient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>
{
    int32_t WINRT_CALL get_BytesSent(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesSent, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BytesSent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor>
{
    int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().ProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributeHandle, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AttributeHandle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadValueAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>>(this->shim().ReadValueAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadValueWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>>(this->shim().ReadValueAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteValueAsync(void* value, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>), Windows::Storage::Streams::IBuffer const);
            *action = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>>(this->shim().WriteValueAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>
{
    int32_t WINRT_CALL WriteValueWithResultAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValueWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>>(this->shim().WriteValueWithResultAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>
{
    int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* descriptorUuid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertShortIdToUuid, WINRT_WRAP(winrt::guid), uint16_t);
            *descriptorUuid = detach_from<winrt::guid>(this->shim().ConvertShortIdToUuid(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>
{
    int32_t WINRT_CALL get_CharacteristicAggregateFormat(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicAggregateFormat, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CharacteristicAggregateFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicExtendedProperties(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicExtendedProperties, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CharacteristicExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicPresentationFormat(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicPresentationFormat, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CharacteristicPresentationFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicUserDescription(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicUserDescription, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CharacteristicUserDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCharacteristicConfiguration(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCharacteristicConfiguration, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ClientCharacteristicConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCharacteristicConfiguration(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCharacteristicConfiguration, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ServerCharacteristicConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>>(this->shim().Descriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService>
{
    int32_t WINRT_CALL GetCharacteristics(winrt::guid characteristicUuid, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>), winrt::guid const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>>(this->shim().GetCharacteristics(*reinterpret_cast<winrt::guid const*>(&characteristicUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIncludedServices(winrt::guid serviceUuid, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIncludedServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>), winrt::guid const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().GetIncludedServices(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
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

    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributeHandle, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().AttributeHandle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothLEDevice));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothLEDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().ParentServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllCharacteristics(void** characteristics) noexcept final
    {
        try
        {
            *characteristics = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllCharacteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>));
            *characteristics = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>>(this->shim().GetAllCharacteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllIncludedServices(void** includedServices) noexcept final
    {
        try
        {
            *includedServices = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllIncludedServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>));
            *includedServices = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().GetAllIncludedServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>
{
    int32_t WINRT_CALL get_DeviceAccessInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAccessInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().DeviceAccessInformation());
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
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode sharingMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus>), Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus>>(this->shim().OpenAsync(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacteristicsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>>(this->shim().GetCharacteristicsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacteristicsWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacteristicsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>>(this->shim().GetCharacteristicsAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacteristicsForUuidAsync(winrt::guid characteristicUuid, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacteristicsForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>), winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>>(this->shim().GetCharacteristicsForUuidAsync(*reinterpret_cast<winrt::guid const*>(&characteristicUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacteristicsForUuidWithCacheModeAsync(winrt::guid characteristicUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacteristicsForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>), winrt::guid const, Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>>(this->shim().GetCharacteristicsForUuidAsync(*reinterpret_cast<winrt::guid const*>(&characteristicUuid), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIncludedServicesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIncludedServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetIncludedServicesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIncludedServicesWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIncludedServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetIncludedServicesAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIncludedServicesForUuidAsync(winrt::guid serviceUuid, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIncludedServicesForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetIncludedServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIncludedServicesForUuidWithCacheModeAsync(winrt::guid serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIncludedServicesForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), winrt::guid const, Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetIncludedServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromUuid(winrt::guid serviceUuid, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromUuid, WINRT_WRAP(hstring), winrt::guid const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorFromUuid(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromShortId(uint16_t serviceShortId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromShortId, WINRT_WRAP(hstring), uint16_t);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorFromShortId(serviceShortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* serviceUuid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertShortIdToUuid, WINRT_WRAP(winrt::guid), uint16_t);
            *serviceUuid = detach_from<winrt::guid>(this->shim().ConvertShortIdToUuid(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>
{
    int32_t WINRT_CALL FromIdWithSharingModeAsync(void* deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode sharingMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>), hstring const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceId(void* bluetoothDeviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceId, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDeviceId const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceId(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDeviceId const*>(&bluetoothDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdWithCacheMode(void* bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceId, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDeviceId const&, Windows::Devices::Bluetooth::BluetoothCacheMode const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceId(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDeviceId const*>(&bluetoothDeviceId), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdAndUuid(void* bluetoothDeviceId, winrt::guid serviceUuid, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceIdAndUuid, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDeviceId const&, winrt::guid const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceIdAndUuid(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDeviceId const*>(&bluetoothDeviceId), *reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdAndUuidWithCacheMode(void* bluetoothDeviceId, winrt::guid serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceIdAndUuid, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDeviceId const&, winrt::guid const&, Windows::Devices::Bluetooth::BluetoothCacheMode const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceIdAndUuid(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDeviceId const*>(&bluetoothDeviceId), *reinterpret_cast<winrt::guid const*>(&serviceUuid), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Services(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Services, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().Services());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>
{
    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaticValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().StaticValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicProperties, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties>(this->shim().CharacteristicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ReadProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().WriteProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDescriptorAsync(winrt::guid descriptorUuid, void* parameters, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDescriptorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult>), winrt::guid const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult>>(this->shim().CreateDescriptorAsync(*reinterpret_cast<winrt::guid const*>(&descriptorUuid), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters const*>(&parameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>>(this->shim().Descriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>>(this->shim().PresentationFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubscribedClients(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscribedClients, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>>(this->shim().SubscribedClients());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SubscribedClientsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscribedClientsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SubscribedClientsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SubscribedClientsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SubscribedClientsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SubscribedClientsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ReadRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReadRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReadRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReadRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_WriteRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().WriteRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WriteRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WriteRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WriteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NotifyValueAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>>), Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>>>(this->shim().NotifyValueAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyValueForSubscribedClientAsync(void* value, void* subscribedClient, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyValueAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>), Windows::Storage::Streams::IBuffer const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>>(this->shim().NotifyValueAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient const*>(&subscribedClient)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters>
{
    int32_t WINRT_CALL put_StaticValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().StaticValue(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaticValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().StaticValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicProperties, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties const&);
            this->shim().CharacteristicProperties(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicProperties, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties>(this->shim().CharacteristicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().ReadProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ReadProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().WriteProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().WriteProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDescription, WINRT_WRAP(void), hstring const&);
            this->shim().UserDescription(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDescription, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationFormats, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>>(this->shim().PresentationFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult>
{
    int32_t WINRT_CALL get_Characteristic(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristic, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>(this->shim().Characteristic());
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
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>
{
    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaticValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().StaticValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ReadProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().WriteProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReadRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReadRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReadRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReadRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_WriteRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().WriteRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WriteRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WriteRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WriteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters>
{
    int32_t WINRT_CALL put_StaticValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().StaticValue(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StaticValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StaticValue, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().StaticValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().ReadProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().ReadProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const&);
            this->shim().WriteProtectionLevel(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteProtectionLevel, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>(this->shim().WriteProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult>
{
    int32_t WINRT_CALL get_Descriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptor, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>(this->shim().Descriptor());
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
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService>
{
    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCharacteristicAsync(winrt::guid characteristicUuid, void* parameters, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCharacteristicAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>), winrt::guid const, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>>(this->shim().CreateCharacteristicAsync(*reinterpret_cast<winrt::guid const*>(&characteristicUuid), *reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters const*>(&parameters)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Characteristics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristics, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>>(this->shim().Characteristics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat>
{
    int32_t WINRT_CALL get_FormatType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().FormatType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Exponent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exponent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Exponent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Unit(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Namespace(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Namespace, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Namespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>
{
    int32_t WINRT_CALL get_BluetoothSigAssignedNumbers(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothSigAssignedNumbers, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().BluetoothSigAssignedNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>
{
    int32_t WINRT_CALL FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromParts, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat), uint8_t, int32_t, uint16_t, uint8_t, uint16_t);
            *result = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>(this->shim().FromParts(formatType, exponent, unit, namespaceId, description));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>
{
    int32_t WINRT_CALL get_Boolean(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Boolean, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Boolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bit2(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bit2, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Bit2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nibble(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nibble, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Nibble());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt8(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt8, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt12(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt12, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt16(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt16, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt24(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt24, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt24());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt32(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt32, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt48(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt48, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt48());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt64(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt64, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UInt128(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UInt128, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UInt128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt8(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt8, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt12(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt12, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt16(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt16, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt24(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt24, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt24());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt32(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt32, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt48(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt48, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt48());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt64(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt64, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SInt128(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SInt128, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SInt128());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Float32(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Float32, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Float32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Float64(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Float64, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Float64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SFloat(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SFloat, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SFloat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Float(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Float, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Float());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DUInt16(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DUInt16, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().DUInt16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Utf8(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Utf8, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Utf8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Utf16(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Utf16, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Utf16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Struct(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Struct, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Struct());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>
{
    int32_t WINRT_CALL get_InvalidHandle(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidHandle, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InvalidHandle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadNotPermitted(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadNotPermitted, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ReadNotPermitted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteNotPermitted(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteNotPermitted, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().WriteNotPermitted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidPdu(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidPdu, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InvalidPdu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientAuthentication(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientAuthentication, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InsufficientAuthentication());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestNotSupported(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNotSupported, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().RequestNotSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidOffset(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidOffset, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InvalidOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientAuthorization(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientAuthorization, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InsufficientAuthorization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrepareQueueFull(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareQueueFull, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().PrepareQueueFull());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributeNotFound(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributeNotFound, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().AttributeNotFound());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributeNotLong(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributeNotLong, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().AttributeNotLong());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientEncryptionKeySize(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientEncryptionKeySize, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InsufficientEncryptionKeySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InvalidAttributeValueLength(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidAttributeValueLength, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InvalidAttributeValueLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnlikelyError(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnlikelyError, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UnlikelyError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientEncryption(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientEncryption, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InsufficientEncryption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnsupportedGroupType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnsupportedGroupType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().UnsupportedGroupType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsufficientResources(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsufficientResources, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InsufficientResources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientCharacteristicConfigurationDescriptor(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientCharacteristicConfigurationDescriptor, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue>(this->shim().ClientCharacteristicConfigurationDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>
{
    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>
{
    int32_t WINRT_CALL get_Offset(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL RespondWithValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RespondWithValue, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().RespondWithValue(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RespondWithProtocolError(uint8_t protocolError) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RespondWithProtocolError, WINRT_WRAP(void), uint8_t);
            this->shim().RespondWithProtocolError(protocolError);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRequestAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest>>(this->shim().GetRequestAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
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

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>
{
    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction>
{
    int32_t WINRT_CALL WriteValue(void* characteristic, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteValue, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const&, Windows::Storage::Streams::IBuffer const&);
            this->shim().WriteValue(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const*>(&characteristic), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CommitAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>>(this->shim().CommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>
{
    int32_t WINRT_CALL CommitWithResultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>>(this->shim().CommitWithResultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState>(this->shim().State());
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
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>
{
    int32_t WINRT_CALL get_Service(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Service, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService>(this->shim().Service());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdvertisementStatus(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementStatus, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus>(this->shim().AdvertisementStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AdvertisementStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvertisementStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AdvertisementStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL StartAdvertising() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAdvertising, WINRT_WRAP(void));
            this->shim().StartAdvertising();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAdvertisingWithParameters(void* parameters) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAdvertising, WINRT_WRAP(void), Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters const&);
            this->shim().StartAdvertising(*reinterpret_cast<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters const*>(&parameters));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAdvertising() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAdvertising, WINRT_WRAP(void));
            this->shim().StopAdvertising();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs>
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

    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters>
{
    int32_t WINRT_CALL put_IsConnectable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnectable, WINRT_WRAP(void), bool);
            this->shim().IsConnectable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConnectable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnectable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConnectable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDiscoverable(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDiscoverable, WINRT_WRAP(void), bool);
            this->shim().IsDiscoverable(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDiscoverable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDiscoverable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDiscoverable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>
{
    int32_t WINRT_CALL put_ServiceData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceData, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().ServiceData(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().ServiceData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult>
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

    int32_t WINRT_CALL get_ServiceProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProvider, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider>(this->shim().ServiceProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>
{
    int32_t WINRT_CALL CreateAsync(winrt::guid serviceUuid, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult>), winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult>>(this->shim().CreateAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>
{
    int32_t WINRT_CALL get_Battery(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Battery, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Battery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressure(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressure, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BloodPressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingSpeedAndCadence(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingSpeedAndCadence, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingSpeedAndCadence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GenericAccess(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenericAccess, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GenericAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GenericAttribute(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenericAttribute, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GenericAttribute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Glucose(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Glucose, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Glucose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HealthThermometer(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HealthThermometer, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HealthThermometer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeartRate(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartRate, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HeartRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RunningSpeedAndCadence(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunningSpeedAndCadence, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().RunningSpeedAndCadence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>
{
    int32_t WINRT_CALL get_AlertNotification(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlertNotification, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().AlertNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentTime(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentTime, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CurrentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPower(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPower, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CyclingPower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInformation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HumanInterfaceDevice(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HumanInterfaceDevice, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HumanInterfaceDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImmediateAlert(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImmediateAlert, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ImmediateAlert());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkLoss(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkLoss, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LinkLoss());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationAndNavigation(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationAndNavigation, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LocationAndNavigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextDstChange(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextDstChange, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NextDstChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneAlertStatus(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneAlertStatus, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PhoneAlertStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReferenceTimeUpdate(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReferenceTimeUpdate, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ReferenceTimeUpdate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScanParameters(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanParameters, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ScanParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TxPower(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TxPower, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TxPower());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDeviceId));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanMaintainConnection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMaintainConnection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanMaintainConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaintainConnection(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaintainConnection, WINRT_WRAP(void), bool);
            this->shim().MaintainConnection(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaintainConnection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaintainConnection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().MaintainConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPduSize(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPduSize, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().MaxPduSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionStatus(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionStatus, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus>(this->shim().SessionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MaxPduSizeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPduSizeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().MaxPduSizeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MaxPduSizeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MaxPduSizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MaxPduSizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SessionStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>
{
    int32_t WINRT_CALL FromDeviceIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromDeviceIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>), Windows::Devices::Bluetooth::BluetoothDeviceId const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>>(this->shim().FromDeviceIdAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDeviceId const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs>
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

    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxNotificationSize(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxNotificationSize, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().MaxNotificationSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MaxNotificationSizeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxNotificationSizeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().MaxNotificationSizeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MaxNotificationSizeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MaxNotificationSizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MaxNotificationSizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs>
{
    int32_t WINRT_CALL get_CharacteristicValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacteristicValue, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CharacteristicValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* timestamp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *timestamp = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>
{
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

    int32_t WINRT_CALL get_Offset(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Option(Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Option, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption>(this->shim().Option());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL Respond() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Respond, WINRT_WRAP(void));
            this->shim().Respond();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RespondWithProtocolError(uint8_t protocolError) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RespondWithProtocolError, WINRT_WRAP(void), uint8_t);
            this->shim().RespondWithProtocolError(protocolError);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRequestAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest>>(this->shim().GetRequestAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult> : produce_base<D, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolError, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile {

inline winrt::guid GattCharacteristic::ConvertShortIdToUuid(uint16_t shortId)
{
    return impl::call_factory<GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>([&](auto&& f) { return f.ConvertShortIdToUuid(shortId); });
}

inline winrt::guid GattCharacteristicUuids::BatteryLevel()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.BatteryLevel(); });
}

inline winrt::guid GattCharacteristicUuids::BloodPressureFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.BloodPressureFeature(); });
}

inline winrt::guid GattCharacteristicUuids::BloodPressureMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.BloodPressureMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::BodySensorLocation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.BodySensorLocation(); });
}

inline winrt::guid GattCharacteristicUuids::CscFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.CscFeature(); });
}

inline winrt::guid GattCharacteristicUuids::CscMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.CscMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::GlucoseFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.GlucoseFeature(); });
}

inline winrt::guid GattCharacteristicUuids::GlucoseMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.GlucoseMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::GlucoseMeasurementContext()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.GlucoseMeasurementContext(); });
}

inline winrt::guid GattCharacteristicUuids::HeartRateControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.HeartRateControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::HeartRateMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.HeartRateMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::IntermediateCuffPressure()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.IntermediateCuffPressure(); });
}

inline winrt::guid GattCharacteristicUuids::IntermediateTemperature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.IntermediateTemperature(); });
}

inline winrt::guid GattCharacteristicUuids::MeasurementInterval()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.MeasurementInterval(); });
}

inline winrt::guid GattCharacteristicUuids::RecordAccessControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.RecordAccessControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::RscFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.RscFeature(); });
}

inline winrt::guid GattCharacteristicUuids::RscMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.RscMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::SCControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.SCControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::SensorLocation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.SensorLocation(); });
}

inline winrt::guid GattCharacteristicUuids::TemperatureMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.TemperatureMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::TemperatureType()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>([&](auto&& f) { return f.TemperatureType(); });
}

inline winrt::guid GattCharacteristicUuids::AlertCategoryId()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.AlertCategoryId(); });
}

inline winrt::guid GattCharacteristicUuids::AlertCategoryIdBitMask()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.AlertCategoryIdBitMask(); });
}

inline winrt::guid GattCharacteristicUuids::AlertLevel()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.AlertLevel(); });
}

inline winrt::guid GattCharacteristicUuids::AlertNotificationControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.AlertNotificationControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::AlertStatus()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.AlertStatus(); });
}

inline winrt::guid GattCharacteristicUuids::GapAppearance()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GapAppearance(); });
}

inline winrt::guid GattCharacteristicUuids::BootKeyboardInputReport()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.BootKeyboardInputReport(); });
}

inline winrt::guid GattCharacteristicUuids::BootKeyboardOutputReport()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.BootKeyboardOutputReport(); });
}

inline winrt::guid GattCharacteristicUuids::BootMouseInputReport()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.BootMouseInputReport(); });
}

inline winrt::guid GattCharacteristicUuids::CurrentTime()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.CurrentTime(); });
}

inline winrt::guid GattCharacteristicUuids::CyclingPowerControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.CyclingPowerControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::CyclingPowerFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.CyclingPowerFeature(); });
}

inline winrt::guid GattCharacteristicUuids::CyclingPowerMeasurement()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.CyclingPowerMeasurement(); });
}

inline winrt::guid GattCharacteristicUuids::CyclingPowerVector()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.CyclingPowerVector(); });
}

inline winrt::guid GattCharacteristicUuids::DateTime()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.DateTime(); });
}

inline winrt::guid GattCharacteristicUuids::DayDateTime()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.DayDateTime(); });
}

inline winrt::guid GattCharacteristicUuids::DayOfWeek()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.DayOfWeek(); });
}

inline winrt::guid GattCharacteristicUuids::GapDeviceName()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GapDeviceName(); });
}

inline winrt::guid GattCharacteristicUuids::DstOffset()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.DstOffset(); });
}

inline winrt::guid GattCharacteristicUuids::ExactTime256()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ExactTime256(); });
}

inline winrt::guid GattCharacteristicUuids::FirmwareRevisionString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.FirmwareRevisionString(); });
}

inline winrt::guid GattCharacteristicUuids::HardwareRevisionString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.HardwareRevisionString(); });
}

inline winrt::guid GattCharacteristicUuids::HidControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.HidControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::HidInformation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.HidInformation(); });
}

inline winrt::guid GattCharacteristicUuids::Ieee1107320601RegulatoryCertificationDataList()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.Ieee1107320601RegulatoryCertificationDataList(); });
}

inline winrt::guid GattCharacteristicUuids::LnControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.LnControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::LnFeature()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.LnFeature(); });
}

inline winrt::guid GattCharacteristicUuids::LocalTimeInformation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.LocalTimeInformation(); });
}

inline winrt::guid GattCharacteristicUuids::LocationAndSpeed()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.LocationAndSpeed(); });
}

inline winrt::guid GattCharacteristicUuids::ManufacturerNameString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ManufacturerNameString(); });
}

inline winrt::guid GattCharacteristicUuids::ModelNumberString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ModelNumberString(); });
}

inline winrt::guid GattCharacteristicUuids::Navigation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.Navigation(); });
}

inline winrt::guid GattCharacteristicUuids::NewAlert()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.NewAlert(); });
}

inline winrt::guid GattCharacteristicUuids::GapPeripheralPreferredConnectionParameters()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GapPeripheralPreferredConnectionParameters(); });
}

inline winrt::guid GattCharacteristicUuids::GapPeripheralPrivacyFlag()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GapPeripheralPrivacyFlag(); });
}

inline winrt::guid GattCharacteristicUuids::PnpId()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.PnpId(); });
}

inline winrt::guid GattCharacteristicUuids::PositionQuality()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.PositionQuality(); });
}

inline winrt::guid GattCharacteristicUuids::ProtocolMode()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ProtocolMode(); });
}

inline winrt::guid GattCharacteristicUuids::GapReconnectionAddress()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GapReconnectionAddress(); });
}

inline winrt::guid GattCharacteristicUuids::ReferenceTimeInformation()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ReferenceTimeInformation(); });
}

inline winrt::guid GattCharacteristicUuids::Report()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.Report(); });
}

inline winrt::guid GattCharacteristicUuids::ReportMap()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ReportMap(); });
}

inline winrt::guid GattCharacteristicUuids::RingerControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.RingerControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::RingerSetting()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.RingerSetting(); });
}

inline winrt::guid GattCharacteristicUuids::ScanIntervalWindow()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ScanIntervalWindow(); });
}

inline winrt::guid GattCharacteristicUuids::ScanRefresh()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.ScanRefresh(); });
}

inline winrt::guid GattCharacteristicUuids::SerialNumberString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.SerialNumberString(); });
}

inline winrt::guid GattCharacteristicUuids::GattServiceChanged()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.GattServiceChanged(); });
}

inline winrt::guid GattCharacteristicUuids::SoftwareRevisionString()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.SoftwareRevisionString(); });
}

inline winrt::guid GattCharacteristicUuids::SupportedNewAlertCategory()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.SupportedNewAlertCategory(); });
}

inline winrt::guid GattCharacteristicUuids::SupportUnreadAlertCategory()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.SupportUnreadAlertCategory(); });
}

inline winrt::guid GattCharacteristicUuids::SystemId()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.SystemId(); });
}

inline winrt::guid GattCharacteristicUuids::TimeAccuracy()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeAccuracy(); });
}

inline winrt::guid GattCharacteristicUuids::TimeSource()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeSource(); });
}

inline winrt::guid GattCharacteristicUuids::TimeUpdateControlPoint()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeUpdateControlPoint(); });
}

inline winrt::guid GattCharacteristicUuids::TimeUpdateState()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeUpdateState(); });
}

inline winrt::guid GattCharacteristicUuids::TimeWithDst()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeWithDst(); });
}

inline winrt::guid GattCharacteristicUuids::TimeZone()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TimeZone(); });
}

inline winrt::guid GattCharacteristicUuids::TxPowerLevel()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.TxPowerLevel(); });
}

inline winrt::guid GattCharacteristicUuids::UnreadAlertStatus()
{
    return impl::call_factory<GattCharacteristicUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>([&](auto&& f) { return f.UnreadAlertStatus(); });
}

inline winrt::guid GattDescriptor::ConvertShortIdToUuid(uint16_t shortId)
{
    return impl::call_factory<GattDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>([&](auto&& f) { return f.ConvertShortIdToUuid(shortId); });
}

inline winrt::guid GattDescriptorUuids::CharacteristicAggregateFormat()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.CharacteristicAggregateFormat(); });
}

inline winrt::guid GattDescriptorUuids::CharacteristicExtendedProperties()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.CharacteristicExtendedProperties(); });
}

inline winrt::guid GattDescriptorUuids::CharacteristicPresentationFormat()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.CharacteristicPresentationFormat(); });
}

inline winrt::guid GattDescriptorUuids::CharacteristicUserDescription()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.CharacteristicUserDescription(); });
}

inline winrt::guid GattDescriptorUuids::ClientCharacteristicConfiguration()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.ClientCharacteristicConfiguration(); });
}

inline winrt::guid GattDescriptorUuids::ServerCharacteristicConfiguration()
{
    return impl::call_factory<GattDescriptorUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>([&](auto&& f) { return f.ServerCharacteristicConfiguration(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> GattDeviceService::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring GattDeviceService::GetDeviceSelectorFromUuid(winrt::guid const& serviceUuid)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>([&](auto&& f) { return f.GetDeviceSelectorFromUuid(serviceUuid); });
}

inline hstring GattDeviceService::GetDeviceSelectorFromShortId(uint16_t serviceShortId)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>([&](auto&& f) { return f.GetDeviceSelectorFromShortId(serviceShortId); });
}

inline winrt::guid GattDeviceService::ConvertShortIdToUuid(uint16_t shortId)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>([&](auto&& f) { return f.ConvertShortIdToUuid(shortId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> GattDeviceService::FromIdAsync(param::hstring const& deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId, sharingMode); });
}

inline hstring GattDeviceService::GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceId(bluetoothDeviceId); });
}

inline hstring GattDeviceService::GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceId(bluetoothDeviceId, cacheMode); });
}

inline hstring GattDeviceService::GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceIdAndUuid(bluetoothDeviceId, serviceUuid); });
}

inline hstring GattDeviceService::GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode)
{
    return impl::call_factory<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceIdAndUuid(bluetoothDeviceId, serviceUuid, cacheMode); });
}

inline GattLocalCharacteristicParameters::GattLocalCharacteristicParameters() :
    GattLocalCharacteristicParameters(impl::call_factory<GattLocalCharacteristicParameters>([](auto&& f) { return f.template ActivateInstance<GattLocalCharacteristicParameters>(); }))
{}

inline GattLocalDescriptorParameters::GattLocalDescriptorParameters() :
    GattLocalDescriptorParameters(impl::call_factory<GattLocalDescriptorParameters>([](auto&& f) { return f.template ActivateInstance<GattLocalDescriptorParameters>(); }))
{}

inline uint8_t GattPresentationFormat::BluetoothSigAssignedNumbers()
{
    return impl::call_factory<GattPresentationFormat, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>([&](auto&& f) { return f.BluetoothSigAssignedNumbers(); });
}

inline Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat GattPresentationFormat::FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description)
{
    return impl::call_factory<GattPresentationFormat, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>([&](auto&& f) { return f.FromParts(formatType, exponent, unit, namespaceId, description); });
}

inline uint8_t GattPresentationFormatTypes::Boolean()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Boolean(); });
}

inline uint8_t GattPresentationFormatTypes::Bit2()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Bit2(); });
}

inline uint8_t GattPresentationFormatTypes::Nibble()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Nibble(); });
}

inline uint8_t GattPresentationFormatTypes::UInt8()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt8(); });
}

inline uint8_t GattPresentationFormatTypes::UInt12()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt12(); });
}

inline uint8_t GattPresentationFormatTypes::UInt16()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt16(); });
}

inline uint8_t GattPresentationFormatTypes::UInt24()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt24(); });
}

inline uint8_t GattPresentationFormatTypes::UInt32()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt32(); });
}

inline uint8_t GattPresentationFormatTypes::UInt48()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt48(); });
}

inline uint8_t GattPresentationFormatTypes::UInt64()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt64(); });
}

inline uint8_t GattPresentationFormatTypes::UInt128()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.UInt128(); });
}

inline uint8_t GattPresentationFormatTypes::SInt8()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt8(); });
}

inline uint8_t GattPresentationFormatTypes::SInt12()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt12(); });
}

inline uint8_t GattPresentationFormatTypes::SInt16()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt16(); });
}

inline uint8_t GattPresentationFormatTypes::SInt24()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt24(); });
}

inline uint8_t GattPresentationFormatTypes::SInt32()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt32(); });
}

inline uint8_t GattPresentationFormatTypes::SInt48()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt48(); });
}

inline uint8_t GattPresentationFormatTypes::SInt64()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt64(); });
}

inline uint8_t GattPresentationFormatTypes::SInt128()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SInt128(); });
}

inline uint8_t GattPresentationFormatTypes::Float32()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Float32(); });
}

inline uint8_t GattPresentationFormatTypes::Float64()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Float64(); });
}

inline uint8_t GattPresentationFormatTypes::SFloat()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.SFloat(); });
}

inline uint8_t GattPresentationFormatTypes::Float()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Float(); });
}

inline uint8_t GattPresentationFormatTypes::DUInt16()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.DUInt16(); });
}

inline uint8_t GattPresentationFormatTypes::Utf8()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Utf8(); });
}

inline uint8_t GattPresentationFormatTypes::Utf16()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Utf16(); });
}

inline uint8_t GattPresentationFormatTypes::Struct()
{
    return impl::call_factory<GattPresentationFormatTypes, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>([&](auto&& f) { return f.Struct(); });
}

inline uint8_t GattProtocolError::InvalidHandle()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InvalidHandle(); });
}

inline uint8_t GattProtocolError::ReadNotPermitted()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.ReadNotPermitted(); });
}

inline uint8_t GattProtocolError::WriteNotPermitted()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.WriteNotPermitted(); });
}

inline uint8_t GattProtocolError::InvalidPdu()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InvalidPdu(); });
}

inline uint8_t GattProtocolError::InsufficientAuthentication()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InsufficientAuthentication(); });
}

inline uint8_t GattProtocolError::RequestNotSupported()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.RequestNotSupported(); });
}

inline uint8_t GattProtocolError::InvalidOffset()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InvalidOffset(); });
}

inline uint8_t GattProtocolError::InsufficientAuthorization()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InsufficientAuthorization(); });
}

inline uint8_t GattProtocolError::PrepareQueueFull()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.PrepareQueueFull(); });
}

inline uint8_t GattProtocolError::AttributeNotFound()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.AttributeNotFound(); });
}

inline uint8_t GattProtocolError::AttributeNotLong()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.AttributeNotLong(); });
}

inline uint8_t GattProtocolError::InsufficientEncryptionKeySize()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InsufficientEncryptionKeySize(); });
}

inline uint8_t GattProtocolError::InvalidAttributeValueLength()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InvalidAttributeValueLength(); });
}

inline uint8_t GattProtocolError::UnlikelyError()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.UnlikelyError(); });
}

inline uint8_t GattProtocolError::InsufficientEncryption()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InsufficientEncryption(); });
}

inline uint8_t GattProtocolError::UnsupportedGroupType()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.UnsupportedGroupType(); });
}

inline uint8_t GattProtocolError::InsufficientResources()
{
    return impl::call_factory<GattProtocolError, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>([&](auto&& f) { return f.InsufficientResources(); });
}

inline GattReliableWriteTransaction::GattReliableWriteTransaction() :
    GattReliableWriteTransaction(impl::call_factory<GattReliableWriteTransaction>([](auto&& f) { return f.template ActivateInstance<GattReliableWriteTransaction>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> GattServiceProvider::CreateAsync(winrt::guid const& serviceUuid)
{
    return impl::call_factory<GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>([&](auto&& f) { return f.CreateAsync(serviceUuid); });
}

inline GattServiceProviderAdvertisingParameters::GattServiceProviderAdvertisingParameters() :
    GattServiceProviderAdvertisingParameters(impl::call_factory<GattServiceProviderAdvertisingParameters>([](auto&& f) { return f.template ActivateInstance<GattServiceProviderAdvertisingParameters>(); }))
{}

inline winrt::guid GattServiceUuids::Battery()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.Battery(); });
}

inline winrt::guid GattServiceUuids::BloodPressure()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.BloodPressure(); });
}

inline winrt::guid GattServiceUuids::CyclingSpeedAndCadence()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.CyclingSpeedAndCadence(); });
}

inline winrt::guid GattServiceUuids::GenericAccess()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.GenericAccess(); });
}

inline winrt::guid GattServiceUuids::GenericAttribute()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.GenericAttribute(); });
}

inline winrt::guid GattServiceUuids::Glucose()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.Glucose(); });
}

inline winrt::guid GattServiceUuids::HealthThermometer()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.HealthThermometer(); });
}

inline winrt::guid GattServiceUuids::HeartRate()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.HeartRate(); });
}

inline winrt::guid GattServiceUuids::RunningSpeedAndCadence()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>([&](auto&& f) { return f.RunningSpeedAndCadence(); });
}

inline winrt::guid GattServiceUuids::AlertNotification()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.AlertNotification(); });
}

inline winrt::guid GattServiceUuids::CurrentTime()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.CurrentTime(); });
}

inline winrt::guid GattServiceUuids::CyclingPower()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.CyclingPower(); });
}

inline winrt::guid GattServiceUuids::DeviceInformation()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.DeviceInformation(); });
}

inline winrt::guid GattServiceUuids::HumanInterfaceDevice()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.HumanInterfaceDevice(); });
}

inline winrt::guid GattServiceUuids::ImmediateAlert()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.ImmediateAlert(); });
}

inline winrt::guid GattServiceUuids::LinkLoss()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.LinkLoss(); });
}

inline winrt::guid GattServiceUuids::LocationAndNavigation()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.LocationAndNavigation(); });
}

inline winrt::guid GattServiceUuids::NextDstChange()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.NextDstChange(); });
}

inline winrt::guid GattServiceUuids::PhoneAlertStatus()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.PhoneAlertStatus(); });
}

inline winrt::guid GattServiceUuids::ReferenceTimeUpdate()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.ReferenceTimeUpdate(); });
}

inline winrt::guid GattServiceUuids::ScanParameters()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.ScanParameters(); });
}

inline winrt::guid GattServiceUuids::TxPower()
{
    return impl::call_factory<GattServiceUuids, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>([&](auto&& f) { return f.TxPower(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> GattSession::FromDeviceIdAsync(Windows::Devices::Bluetooth::BluetoothDeviceId const& deviceId)
{
    return impl::call_factory<GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>([&](auto&& f) { return f.FromDeviceIdAsync(deviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicUuids> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicUuids> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorUuids> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorUuids> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormatTypes> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormatTypes> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtocolError> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtocolError> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReliableWriteTransaction> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattReliableWriteTransaction> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceUuids> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceUuids> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> {};

}
