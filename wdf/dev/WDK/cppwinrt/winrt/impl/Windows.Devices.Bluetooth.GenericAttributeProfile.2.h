// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Bluetooth.1.h"
#include "winrt/impl/Windows.Devices.Enumeration.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile {

struct WINRT_EBO GattCharacteristic :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic,
    impl::require<GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>
{
    GattCharacteristic(std::nullptr_t) noexcept {}
    static winrt::guid ConvertShortIdToUuid(uint16_t shortId);
};

struct GattCharacteristicUuids
{
    GattCharacteristicUuids() = delete;
    static winrt::guid BatteryLevel();
    static winrt::guid BloodPressureFeature();
    static winrt::guid BloodPressureMeasurement();
    static winrt::guid BodySensorLocation();
    static winrt::guid CscFeature();
    static winrt::guid CscMeasurement();
    static winrt::guid GlucoseFeature();
    static winrt::guid GlucoseMeasurement();
    static winrt::guid GlucoseMeasurementContext();
    static winrt::guid HeartRateControlPoint();
    static winrt::guid HeartRateMeasurement();
    static winrt::guid IntermediateCuffPressure();
    static winrt::guid IntermediateTemperature();
    static winrt::guid MeasurementInterval();
    static winrt::guid RecordAccessControlPoint();
    static winrt::guid RscFeature();
    static winrt::guid RscMeasurement();
    static winrt::guid SCControlPoint();
    static winrt::guid SensorLocation();
    static winrt::guid TemperatureMeasurement();
    static winrt::guid TemperatureType();
    static winrt::guid AlertCategoryId();
    static winrt::guid AlertCategoryIdBitMask();
    static winrt::guid AlertLevel();
    static winrt::guid AlertNotificationControlPoint();
    static winrt::guid AlertStatus();
    static winrt::guid GapAppearance();
    static winrt::guid BootKeyboardInputReport();
    static winrt::guid BootKeyboardOutputReport();
    static winrt::guid BootMouseInputReport();
    static winrt::guid CurrentTime();
    static winrt::guid CyclingPowerControlPoint();
    static winrt::guid CyclingPowerFeature();
    static winrt::guid CyclingPowerMeasurement();
    static winrt::guid CyclingPowerVector();
    static winrt::guid DateTime();
    static winrt::guid DayDateTime();
    static winrt::guid DayOfWeek();
    static winrt::guid GapDeviceName();
    static winrt::guid DstOffset();
    static winrt::guid ExactTime256();
    static winrt::guid FirmwareRevisionString();
    static winrt::guid HardwareRevisionString();
    static winrt::guid HidControlPoint();
    static winrt::guid HidInformation();
    static winrt::guid Ieee1107320601RegulatoryCertificationDataList();
    static winrt::guid LnControlPoint();
    static winrt::guid LnFeature();
    static winrt::guid LocalTimeInformation();
    static winrt::guid LocationAndSpeed();
    static winrt::guid ManufacturerNameString();
    static winrt::guid ModelNumberString();
    static winrt::guid Navigation();
    static winrt::guid NewAlert();
    static winrt::guid GapPeripheralPreferredConnectionParameters();
    static winrt::guid GapPeripheralPrivacyFlag();
    static winrt::guid PnpId();
    static winrt::guid PositionQuality();
    static winrt::guid ProtocolMode();
    static winrt::guid GapReconnectionAddress();
    static winrt::guid ReferenceTimeInformation();
    static winrt::guid Report();
    static winrt::guid ReportMap();
    static winrt::guid RingerControlPoint();
    static winrt::guid RingerSetting();
    static winrt::guid ScanIntervalWindow();
    static winrt::guid ScanRefresh();
    static winrt::guid SerialNumberString();
    static winrt::guid GattServiceChanged();
    static winrt::guid SoftwareRevisionString();
    static winrt::guid SupportedNewAlertCategory();
    static winrt::guid SupportUnreadAlertCategory();
    static winrt::guid SystemId();
    static winrt::guid TimeAccuracy();
    static winrt::guid TimeSource();
    static winrt::guid TimeUpdateControlPoint();
    static winrt::guid TimeUpdateState();
    static winrt::guid TimeWithDst();
    static winrt::guid TimeZone();
    static winrt::guid TxPowerLevel();
    static winrt::guid UnreadAlertStatus();
};

struct WINRT_EBO GattCharacteristicsResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult
{
    GattCharacteristicsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattClientNotificationResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult,
    impl::require<GattClientNotificationResult, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>
{
    GattClientNotificationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattDescriptor :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor,
    impl::require<GattDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>
{
    GattDescriptor(std::nullptr_t) noexcept {}
    static winrt::guid ConvertShortIdToUuid(uint16_t shortId);
};

struct GattDescriptorUuids
{
    GattDescriptorUuids() = delete;
    static winrt::guid CharacteristicAggregateFormat();
    static winrt::guid CharacteristicExtendedProperties();
    static winrt::guid CharacteristicPresentationFormat();
    static winrt::guid CharacteristicUserDescription();
    static winrt::guid ClientCharacteristicConfiguration();
    static winrt::guid ServerCharacteristicConfiguration();
};

struct WINRT_EBO GattDescriptorsResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult
{
    GattDescriptorsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattDeviceService :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService,
    impl::require<GattDeviceService, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>
{
    GattDeviceService(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> FromIdAsync(param::hstring const& deviceId);
    static hstring GetDeviceSelectorFromUuid(winrt::guid const& serviceUuid);
    static hstring GetDeviceSelectorFromShortId(uint16_t serviceShortId);
    static winrt::guid ConvertShortIdToUuid(uint16_t shortId);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> FromIdAsync(param::hstring const& deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode);
    static hstring GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId);
    static hstring GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode);
    static hstring GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid);
    static hstring GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode);
};

struct WINRT_EBO GattDeviceServicesResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult
{
    GattDeviceServicesResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattLocalCharacteristic :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic
{
    GattLocalCharacteristic(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattLocalCharacteristicParameters :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters
{
    GattLocalCharacteristicParameters(std::nullptr_t) noexcept {}
    GattLocalCharacteristicParameters();
};

struct WINRT_EBO GattLocalCharacteristicResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult
{
    GattLocalCharacteristicResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattLocalDescriptor :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor
{
    GattLocalDescriptor(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattLocalDescriptorParameters :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters
{
    GattLocalDescriptorParameters(std::nullptr_t) noexcept {}
    GattLocalDescriptorParameters();
};

struct WINRT_EBO GattLocalDescriptorResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult
{
    GattLocalDescriptorResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattLocalService :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService
{
    GattLocalService(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattPresentationFormat :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat
{
    GattPresentationFormat(std::nullptr_t) noexcept {}
    static uint8_t BluetoothSigAssignedNumbers();
    static Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description);
};

struct GattPresentationFormatTypes
{
    GattPresentationFormatTypes() = delete;
    static uint8_t Boolean();
    static uint8_t Bit2();
    static uint8_t Nibble();
    static uint8_t UInt8();
    static uint8_t UInt12();
    static uint8_t UInt16();
    static uint8_t UInt24();
    static uint8_t UInt32();
    static uint8_t UInt48();
    static uint8_t UInt64();
    static uint8_t UInt128();
    static uint8_t SInt8();
    static uint8_t SInt12();
    static uint8_t SInt16();
    static uint8_t SInt24();
    static uint8_t SInt32();
    static uint8_t SInt48();
    static uint8_t SInt64();
    static uint8_t SInt128();
    static uint8_t Float32();
    static uint8_t Float64();
    static uint8_t SFloat();
    static uint8_t Float();
    static uint8_t DUInt16();
    static uint8_t Utf8();
    static uint8_t Utf16();
    static uint8_t Struct();
};

struct GattProtocolError
{
    GattProtocolError() = delete;
    static uint8_t InvalidHandle();
    static uint8_t ReadNotPermitted();
    static uint8_t WriteNotPermitted();
    static uint8_t InvalidPdu();
    static uint8_t InsufficientAuthentication();
    static uint8_t RequestNotSupported();
    static uint8_t InvalidOffset();
    static uint8_t InsufficientAuthorization();
    static uint8_t PrepareQueueFull();
    static uint8_t AttributeNotFound();
    static uint8_t AttributeNotLong();
    static uint8_t InsufficientEncryptionKeySize();
    static uint8_t InvalidAttributeValueLength();
    static uint8_t UnlikelyError();
    static uint8_t InsufficientEncryption();
    static uint8_t UnsupportedGroupType();
    static uint8_t InsufficientResources();
};

struct WINRT_EBO GattReadClientCharacteristicConfigurationDescriptorResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult,
    impl::require<GattReadClientCharacteristicConfigurationDescriptorResult, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>
{
    GattReadClientCharacteristicConfigurationDescriptorResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattReadRequest :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest
{
    GattReadRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattReadRequestedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs
{
    GattReadRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattReadResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult,
    impl::require<GattReadResult, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>
{
    GattReadResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattReliableWriteTransaction :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction,
    impl::require<GattReliableWriteTransaction, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>
{
    GattReliableWriteTransaction(std::nullptr_t) noexcept {}
    GattReliableWriteTransaction();
};

struct WINRT_EBO GattRequestStateChangedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs
{
    GattRequestStateChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattServiceProvider :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider
{
    GattServiceProvider(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> CreateAsync(winrt::guid const& serviceUuid);
};

struct WINRT_EBO GattServiceProviderAdvertisementStatusChangedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs
{
    GattServiceProviderAdvertisementStatusChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattServiceProviderAdvertisingParameters :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters,
    impl::require<GattServiceProviderAdvertisingParameters, Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>
{
    GattServiceProviderAdvertisingParameters(std::nullptr_t) noexcept {}
    GattServiceProviderAdvertisingParameters();
};

struct WINRT_EBO GattServiceProviderResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult
{
    GattServiceProviderResult(std::nullptr_t) noexcept {}
};

struct GattServiceUuids
{
    GattServiceUuids() = delete;
    static winrt::guid Battery();
    static winrt::guid BloodPressure();
    static winrt::guid CyclingSpeedAndCadence();
    static winrt::guid GenericAccess();
    static winrt::guid GenericAttribute();
    static winrt::guid Glucose();
    static winrt::guid HealthThermometer();
    static winrt::guid HeartRate();
    static winrt::guid RunningSpeedAndCadence();
    static winrt::guid AlertNotification();
    static winrt::guid CurrentTime();
    static winrt::guid CyclingPower();
    static winrt::guid DeviceInformation();
    static winrt::guid HumanInterfaceDevice();
    static winrt::guid ImmediateAlert();
    static winrt::guid LinkLoss();
    static winrt::guid LocationAndNavigation();
    static winrt::guid NextDstChange();
    static winrt::guid PhoneAlertStatus();
    static winrt::guid ReferenceTimeUpdate();
    static winrt::guid ScanParameters();
    static winrt::guid TxPower();
};

struct WINRT_EBO GattSession :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession,
    impl::require<GattSession, Windows::Foundation::IClosable>
{
    GattSession(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> FromDeviceIdAsync(Windows::Devices::Bluetooth::BluetoothDeviceId const& deviceId);
};

struct WINRT_EBO GattSessionStatusChangedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs
{
    GattSessionStatusChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattSubscribedClient :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient
{
    GattSubscribedClient(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattValueChangedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs
{
    GattValueChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattWriteRequest :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest
{
    GattWriteRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattWriteRequestedEventArgs :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs
{
    GattWriteRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GattWriteResult :
    Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult
{
    GattWriteResult(std::nullptr_t) noexcept {}
};

}
