// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth {

enum class BluetoothCacheMode;
enum class BluetoothError;
struct BluetoothDeviceId;
struct BluetoothLEDevice;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

enum class DeviceAccessStatus;
struct DeviceAccessInformation;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile {

enum class GattCharacteristicProperties : uint32_t
{
    None = 0x0,
    Broadcast = 0x1,
    Read = 0x2,
    WriteWithoutResponse = 0x4,
    Write = 0x8,
    Notify = 0x10,
    Indicate = 0x20,
    AuthenticatedSignedWrites = 0x40,
    ExtendedProperties = 0x80,
    ReliableWrites = 0x100,
    WritableAuxiliaries = 0x200,
};

enum class GattClientCharacteristicConfigurationDescriptorValue : int32_t
{
    None = 0,
    Notify = 1,
    Indicate = 2,
};

enum class GattCommunicationStatus : int32_t
{
    Success = 0,
    Unreachable = 1,
    ProtocolError = 2,
    AccessDenied = 3,
};

enum class GattOpenStatus : int32_t
{
    Unspecified = 0,
    Success = 1,
    AlreadyOpened = 2,
    NotFound = 3,
    SharingViolation = 4,
    AccessDenied = 5,
};

enum class GattProtectionLevel : int32_t
{
    Plain = 0,
    AuthenticationRequired = 1,
    EncryptionRequired = 2,
    EncryptionAndAuthenticationRequired = 3,
};

enum class GattRequestState : int32_t
{
    Pending = 0,
    Completed = 1,
    Canceled = 2,
};

enum class GattServiceProviderAdvertisementStatus : int32_t
{
    Created = 0,
    Stopped = 1,
    Started = 2,
    Aborted = 3,
    StartedWithoutAllAdvertisementData = 4,
};

enum class GattSessionStatus : int32_t
{
    Closed = 0,
    Active = 1,
};

enum class GattSharingMode : int32_t
{
    Unspecified = 0,
    Exclusive = 1,
    SharedReadOnly = 2,
    SharedReadAndWrite = 3,
};

enum class GattWriteOption : int32_t
{
    WriteWithResponse = 0,
    WriteWithoutResponse = 1,
};

struct IGattCharacteristic;
struct IGattCharacteristic2;
struct IGattCharacteristic3;
struct IGattCharacteristicStatics;
struct IGattCharacteristicUuidsStatics;
struct IGattCharacteristicUuidsStatics2;
struct IGattCharacteristicsResult;
struct IGattClientNotificationResult;
struct IGattClientNotificationResult2;
struct IGattDescriptor;
struct IGattDescriptor2;
struct IGattDescriptorStatics;
struct IGattDescriptorUuidsStatics;
struct IGattDescriptorsResult;
struct IGattDeviceService;
struct IGattDeviceService2;
struct IGattDeviceService3;
struct IGattDeviceServiceStatics;
struct IGattDeviceServiceStatics2;
struct IGattDeviceServicesResult;
struct IGattLocalCharacteristic;
struct IGattLocalCharacteristicParameters;
struct IGattLocalCharacteristicResult;
struct IGattLocalDescriptor;
struct IGattLocalDescriptorParameters;
struct IGattLocalDescriptorResult;
struct IGattLocalService;
struct IGattPresentationFormat;
struct IGattPresentationFormatStatics;
struct IGattPresentationFormatStatics2;
struct IGattPresentationFormatTypesStatics;
struct IGattProtocolErrorStatics;
struct IGattReadClientCharacteristicConfigurationDescriptorResult;
struct IGattReadClientCharacteristicConfigurationDescriptorResult2;
struct IGattReadRequest;
struct IGattReadRequestedEventArgs;
struct IGattReadResult;
struct IGattReadResult2;
struct IGattReliableWriteTransaction;
struct IGattReliableWriteTransaction2;
struct IGattRequestStateChangedEventArgs;
struct IGattServiceProvider;
struct IGattServiceProviderAdvertisementStatusChangedEventArgs;
struct IGattServiceProviderAdvertisingParameters;
struct IGattServiceProviderAdvertisingParameters2;
struct IGattServiceProviderResult;
struct IGattServiceProviderStatics;
struct IGattServiceUuidsStatics;
struct IGattServiceUuidsStatics2;
struct IGattSession;
struct IGattSessionStatics;
struct IGattSessionStatusChangedEventArgs;
struct IGattSubscribedClient;
struct IGattValueChangedEventArgs;
struct IGattWriteRequest;
struct IGattWriteRequestedEventArgs;
struct IGattWriteResult;
struct GattCharacteristic;
struct GattCharacteristicUuids;
struct GattCharacteristicsResult;
struct GattClientNotificationResult;
struct GattDescriptor;
struct GattDescriptorUuids;
struct GattDescriptorsResult;
struct GattDeviceService;
struct GattDeviceServicesResult;
struct GattLocalCharacteristic;
struct GattLocalCharacteristicParameters;
struct GattLocalCharacteristicResult;
struct GattLocalDescriptor;
struct GattLocalDescriptorParameters;
struct GattLocalDescriptorResult;
struct GattLocalService;
struct GattPresentationFormat;
struct GattPresentationFormatTypes;
struct GattProtocolError;
struct GattReadClientCharacteristicConfigurationDescriptorResult;
struct GattReadRequest;
struct GattReadRequestedEventArgs;
struct GattReadResult;
struct GattReliableWriteTransaction;
struct GattRequestStateChangedEventArgs;
struct GattServiceProvider;
struct GattServiceProviderAdvertisementStatusChangedEventArgs;
struct GattServiceProviderAdvertisingParameters;
struct GattServiceProviderResult;
struct GattServiceUuids;
struct GattSession;
struct GattSessionStatusChangedEventArgs;
struct GattSubscribedClient;
struct GattValueChangedEventArgs;
struct GattWriteRequest;
struct GattWriteRequestedEventArgs;
struct GattWriteResult;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties> : std::true_type {};
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicUuids>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorUuids>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormatTypes>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtocolError>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReliableWriteTransaction>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceUuids>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode>{ using type = enum_category; };
template <> struct category<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption>{ using type = enum_category; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristic" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristic2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristic3" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristicStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristicUuidsStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristicUuidsStatics2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattCharacteristicsResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattClientNotificationResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattClientNotificationResult2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDescriptor" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDescriptor2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDescriptorStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDescriptorUuidsStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDescriptorsResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceService" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceService2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceService3" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceServiceStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceServiceStatics2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattDeviceServicesResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalCharacteristic" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalCharacteristicParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalCharacteristicResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalDescriptor" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalDescriptorParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalDescriptorResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattLocalService" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattPresentationFormat" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattPresentationFormatStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattPresentationFormatStatics2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattPresentationFormatTypesStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattProtocolErrorStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadClientCharacteristicConfigurationDescriptorResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadClientCharacteristicConfigurationDescriptorResult2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadRequest" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReadResult2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReliableWriteTransaction" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattReliableWriteTransaction2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattRequestStateChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProvider" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProviderAdvertisementStatusChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProviderAdvertisingParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProviderAdvertisingParameters2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProviderResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceProviderStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceUuidsStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattServiceUuidsStatics2" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattSession" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattSessionStatics" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattSessionStatusChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattSubscribedClient" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattValueChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattWriteRequest" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattWriteRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.IGattWriteResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristic" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicUuids>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicUuids" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicsResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattClientNotificationResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattDescriptor" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorUuids>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattDescriptorUuids" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattDescriptorsResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattDeviceService" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattDeviceServicesResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalCharacteristic" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalCharacteristicParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalCharacteristicResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalDescriptor" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalDescriptorParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalDescriptorResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattLocalService" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattPresentationFormat" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormatTypes>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattPresentationFormatTypes" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtocolError>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattProtocolError" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadClientCharacteristicConfigurationDescriptorResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadRequest" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattReadResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReliableWriteTransaction>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattReliableWriteTransaction" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattRequestStateChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProvider" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderAdvertisementStatusChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderAdvertisingParameters" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceUuids>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceUuids" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattSession" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattSessionStatusChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattSubscribedClient" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattValueChangedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattWriteRequest" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattWriteRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattWriteResult" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattCharacteristicProperties" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattClientCharacteristicConfigurationDescriptorValue" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattCommunicationStatus" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattOpenStatus" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattProtectionLevel" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattRequestState" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattServiceProviderAdvertisementStatus" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattSessionStatus" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattSharingMode" }; };
template <> struct name<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption>{ static constexpr auto & value{ L"Windows.Devices.Bluetooth.GenericAttributeProfile.GattWriteOption" }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>{ static constexpr guid value{ 0x59CB50C1,0x5934,0x4F68,{ 0xA1,0x98,0xEB,0x86,0x4F,0xA4,0x4E,0x6B } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2>{ static constexpr guid value{ 0xAE1AB578,0xEC06,0x4764,{ 0xB7,0x80,0x98,0x35,0xA1,0xD3,0x5D,0x6E } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>{ static constexpr guid value{ 0x3F3C663E,0x93D4,0x406B,{ 0xB8,0x17,0xDB,0x81,0xF8,0xED,0x53,0xB3 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>{ static constexpr guid value{ 0x59CB50C3,0x5934,0x4F68,{ 0xA1,0x98,0xEB,0x86,0x4F,0xA4,0x4E,0x6B } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>{ static constexpr guid value{ 0x58FA4586,0xB1DE,0x470C,{ 0xB7,0xDE,0x0D,0x11,0xFF,0x44,0xF4,0xB7 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>{ static constexpr guid value{ 0x1855B425,0xD46E,0x4A2C,{ 0x9C,0x3F,0xED,0x6D,0xEA,0x29,0xE7,0xBE } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult>{ static constexpr guid value{ 0x1194945C,0xB257,0x4F3E,{ 0x9D,0xB7,0xF6,0x8B,0xC9,0xA9,0xAE,0xF2 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult>{ static constexpr guid value{ 0x506D5599,0x0112,0x419A,{ 0x8E,0x3B,0xAE,0x21,0xAF,0xAB,0xD2,0xC2 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>{ static constexpr guid value{ 0x8FAEC497,0x45E0,0x497E,{ 0x95,0x82,0x29,0xA1,0xFE,0x28,0x1A,0xD5 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor>{ static constexpr guid value{ 0x92055F2B,0x8084,0x4344,{ 0xB4,0xC2,0x28,0x4D,0xE1,0x9A,0x85,0x06 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>{ static constexpr guid value{ 0x8F563D39,0xD630,0x406C,{ 0xBA,0x11,0x10,0xCD,0xD1,0x6B,0x0E,0x5E } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>{ static constexpr guid value{ 0x92055F2D,0x8084,0x4344,{ 0xB4,0xC2,0x28,0x4D,0xE1,0x9A,0x85,0x06 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>{ static constexpr guid value{ 0xA6F862CE,0x9CFC,0x42F1,{ 0x91,0x85,0xFF,0x37,0xB7,0x51,0x81,0xD3 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult>{ static constexpr guid value{ 0x9BC091F3,0x95E7,0x4489,{ 0x8D,0x25,0xFF,0x81,0x95,0x5A,0x57,0xB9 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService>{ static constexpr guid value{ 0xAC7B7C05,0xB33C,0x47CF,{ 0x99,0x0F,0x6B,0x8F,0x55,0x77,0xDF,0x71 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2>{ static constexpr guid value{ 0xFC54520B,0x0B0D,0x4708,{ 0xBA,0xE0,0x9F,0xFD,0x94,0x89,0xBC,0x59 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>{ static constexpr guid value{ 0xB293A950,0x0C53,0x437C,{ 0xA9,0xB3,0x5C,0x32,0x10,0xC6,0xE5,0x69 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>{ static constexpr guid value{ 0x196D0022,0xFAAD,0x45DC,{ 0xAE,0x5B,0x2A,0xC3,0x18,0x4E,0x84,0xDB } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>{ static constexpr guid value{ 0x0604186E,0x24A6,0x4B0D,{ 0xA2,0xF2,0x30,0xCC,0x01,0x54,0x5D,0x25 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult>{ static constexpr guid value{ 0x171DD3EE,0x016D,0x419D,{ 0x83,0x8A,0x57,0x6C,0xF4,0x75,0xA3,0xD8 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>{ static constexpr guid value{ 0xAEDE376D,0x5412,0x4D74,{ 0x92,0xA8,0x8D,0xEB,0x85,0x26,0x82,0x9C } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters>{ static constexpr guid value{ 0xFAF73DB4,0x4CFF,0x44C7,{ 0x84,0x45,0x04,0x0E,0x6E,0xAD,0x00,0x63 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult>{ static constexpr guid value{ 0x7975DE9B,0x0170,0x4397,{ 0x96,0x66,0x92,0xF8,0x63,0xF1,0x2E,0xE6 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>{ static constexpr guid value{ 0xF48EBE06,0x789D,0x4A4B,{ 0x86,0x52,0xBD,0x01,0x7B,0x5D,0x2F,0xC6 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters>{ static constexpr guid value{ 0x5FDEDE6A,0xF3C1,0x4B66,{ 0x8C,0x4B,0xE3,0xD2,0x29,0x3B,0x40,0xE9 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult>{ static constexpr guid value{ 0x375791BE,0x321F,0x4366,{ 0xBF,0xC1,0x3B,0xC6,0xB8,0x2C,0x79,0xF8 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService>{ static constexpr guid value{ 0xF513E258,0xF7F7,0x4902,{ 0xB8,0x03,0x57,0xFC,0xC7,0xD6,0xFE,0x83 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat>{ static constexpr guid value{ 0x196D0021,0xFAAD,0x45DC,{ 0xAE,0x5B,0x2A,0xC3,0x18,0x4E,0x84,0xDB } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>{ static constexpr guid value{ 0x196D0020,0xFAAD,0x45DC,{ 0xAE,0x5B,0x2A,0xC3,0x18,0x4E,0x84,0xDB } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>{ static constexpr guid value{ 0xA9C21713,0xB82F,0x435E,{ 0xB6,0x34,0x21,0xFD,0x85,0xA4,0x3C,0x07 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>{ static constexpr guid value{ 0xFAF1BA0A,0x30BA,0x409C,{ 0xBE,0xF7,0xCF,0xFB,0x6D,0x03,0xB8,0xFB } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>{ static constexpr guid value{ 0xCA46C5C5,0x0ECC,0x4809,{ 0xBE,0xA3,0xCF,0x79,0xBC,0x99,0x1E,0x37 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult>{ static constexpr guid value{ 0x63A66F09,0x1AEA,0x4C4C,{ 0xA5,0x0F,0x97,0xBA,0xE4,0x74,0xB3,0x48 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>{ static constexpr guid value{ 0x1BF1A59D,0xBA4D,0x4622,{ 0x86,0x51,0xF4,0xEE,0x15,0x0D,0x0A,0x5D } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>{ static constexpr guid value{ 0xF1DD6535,0x6ACD,0x42A6,{ 0xA4,0xBB,0xD7,0x89,0xDA,0xE0,0x04,0x3E } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs>{ static constexpr guid value{ 0x93497243,0xF39C,0x484B,{ 0x8A,0xB6,0x99,0x6B,0xA4,0x86,0xCF,0xA3 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult>{ static constexpr guid value{ 0x63A66F08,0x1AEA,0x4C4C,{ 0xA5,0x0F,0x97,0xBA,0xE4,0x74,0xB3,0x48 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>{ static constexpr guid value{ 0xA10F50A0,0xFB43,0x48AF,{ 0xBA,0xAA,0x63,0x8A,0x5C,0x63,0x29,0xFE } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction>{ static constexpr guid value{ 0x63A66F07,0x1AEA,0x4C4C,{ 0xA5,0x0F,0x97,0xBA,0xE4,0x74,0xB3,0x48 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>{ static constexpr guid value{ 0x51113987,0xEF12,0x462F,{ 0x9F,0xB2,0xA1,0xA4,0x3A,0x67,0x94,0x16 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs>{ static constexpr guid value{ 0xE834D92C,0x27BE,0x44B3,{ 0x9D,0x0D,0x4F,0xC6,0xE8,0x08,0xDD,0x3F } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>{ static constexpr guid value{ 0x7822B3CD,0x2889,0x4F86,{ 0xA0,0x51,0x3F,0x0A,0xED,0x1C,0x27,0x60 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs>{ static constexpr guid value{ 0x59A5AA65,0xFA21,0x4FFC,{ 0xB1,0x55,0x04,0xD9,0x28,0x01,0x26,0x86 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters>{ static constexpr guid value{ 0xE2CE31AB,0x6315,0x4C22,{ 0x9B,0xD7,0x78,0x1D,0xBC,0x3D,0x8D,0x82 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>{ static constexpr guid value{ 0xFF68468D,0xCA92,0x4434,{ 0x97,0x43,0x0E,0x90,0x98,0x8A,0xD8,0x79 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult>{ static constexpr guid value{ 0x764696D8,0xC53E,0x428C,{ 0x8A,0x48,0x67,0xAF,0xE0,0x2C,0x3A,0xE6 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>{ static constexpr guid value{ 0x31794063,0x5256,0x4054,{ 0xA4,0xF4,0x7B,0xBE,0x77,0x55,0xA5,0x7E } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>{ static constexpr guid value{ 0x6DC57058,0x9ABA,0x4417,{ 0xB8,0xF2,0xDC,0xE0,0x16,0xD3,0x4E,0xE2 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>{ static constexpr guid value{ 0xD2AE94F5,0x3D15,0x4F79,{ 0x9C,0x0C,0xEA,0xAF,0xA6,0x75,0x15,0x5C } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>{ static constexpr guid value{ 0xD23B5143,0xE04E,0x4C24,{ 0x99,0x9C,0x9C,0x25,0x6F,0x98,0x56,0xB1 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>{ static constexpr guid value{ 0x2E65B95C,0x539F,0x4DB7,{ 0x82,0xA8,0x73,0xBD,0xBB,0xF7,0x3E,0xBF } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs>{ static constexpr guid value{ 0x7605B72E,0x837F,0x404C,{ 0xAB,0x34,0x31,0x63,0xF3,0x9D,0xDF,0x32 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>{ static constexpr guid value{ 0x736E9001,0x15A4,0x4EC2,{ 0x92,0x48,0xE3,0xF2,0x0D,0x46,0x3B,0xE9 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs>{ static constexpr guid value{ 0xD21BDB54,0x06E3,0x4ED8,{ 0xA2,0x63,0xAC,0xFA,0xC8,0xBA,0x73,0x13 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>{ static constexpr guid value{ 0xAEB6A9ED,0xDE2F,0x4FC2,{ 0xA9,0xA8,0x94,0xEA,0x78,0x44,0xF1,0x3D } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs>{ static constexpr guid value{ 0x2DEC8BBE,0xA73A,0x471A,{ 0x94,0xD5,0x03,0x7D,0xEA,0xDD,0x08,0x06 } }; };
template <> struct guid_storage<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult>{ static constexpr guid value{ 0x4991DDB1,0xCB2B,0x44F7,{ 0x99,0xFC,0xD2,0x9A,0x28,0x71,0xDC,0x9B } }; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReliableWriteTransaction>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs; };
template <> struct default_interface<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult>{ using type = Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult; };

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDescriptors(winrt::guid descriptorUuid, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReadValueAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReadValueWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL WriteValueAsync(void* value, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL WriteValueWithOptionAsync(void* value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption writeOption, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL ReadClientCharacteristicConfigurationDescriptorAsync(void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL WriteClientCharacteristicConfigurationDescriptorAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue clientCharacteristicConfigurationDescriptorValue, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL add_ValueChanged(void* valueChangedHandler, winrt::event_token* valueChangedEventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ValueChanged(winrt::event_token valueChangedEventCookie) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Service(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAllDescriptors(void** descriptors) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDescriptorsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDescriptorsWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDescriptorsForUuidAsync(winrt::guid descriptorUuid, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDescriptorsForUuidWithCacheModeAsync(winrt::guid descriptorUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL WriteValueWithResultAsync(void* value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL WriteValueWithResultAndOptionAsync(void* value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption writeOption, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL WriteClientCharacteristicConfigurationDescriptorWithResultAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue clientCharacteristicConfigurationDescriptorValue, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* characteristicUuid) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BatteryLevel(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BloodPressureFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BloodPressureMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BodySensorLocation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CscFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CscMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GlucoseFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GlucoseMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GlucoseMeasurementContext(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeartRateControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeartRateMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IntermediateCuffPressure(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IntermediateTemperature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MeasurementInterval(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecordAccessControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RscFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RscMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SCControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SensorLocation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TemperatureMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TemperatureType(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AlertCategoryId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlertCategoryIdBitMask(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlertLevel(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlertNotificationControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlertStatus(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GapAppearance(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BootKeyboardInputReport(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BootKeyboardOutputReport(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BootMouseInputReport(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentTime(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingPowerControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingPowerFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingPowerMeasurement(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingPowerVector(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DateTime(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DayDateTime(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DayOfWeek(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GapDeviceName(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DstOffset(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExactTime256(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirmwareRevisionString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareRevisionString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HidControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HidInformation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ieee1107320601RegulatoryCertificationDataList(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LnControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LnFeature(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocalTimeInformation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocationAndSpeed(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ManufacturerNameString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModelNumberString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Navigation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewAlert(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GapPeripheralPreferredConnectionParameters(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GapPeripheralPrivacyFlag(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PnpId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionQuality(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolMode(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GapReconnectionAddress(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReferenceTimeInformation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Report(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReportMap(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RingerControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RingerSetting(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScanIntervalWindow(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScanRefresh(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SerialNumberString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GattServiceChanged(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SoftwareRevisionString(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedNewAlertCategory(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportUnreadAlertCategory(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeAccuracy(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeSource(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeUpdateControlPoint(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeUpdateState(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeWithDst(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeZone(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TxPowerLevel(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnreadAlertStatus(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Characteristics(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SubscribedClient(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BytesSent(uint16_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL ReadValueAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ReadValueWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL WriteValueAsync(void* value, void** action) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL WriteValueWithResultAsync(void* value, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* descriptorUuid) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CharacteristicAggregateFormat(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicExtendedProperties(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicPresentationFormat(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicUserDescription(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClientCharacteristicConfiguration(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCharacteristicConfiguration(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Descriptors(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCharacteristics(winrt::guid characteristicUuid, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetIncludedServices(winrt::guid serviceUuid, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttributeHandle(uint16_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ParentServices(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAllCharacteristics(void** characteristics) noexcept = 0;
    virtual int32_t WINRT_CALL GetAllIncludedServices(void** includedServices) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceAccessInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharingMode(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode sharingMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacteristicsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacteristicsWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacteristicsForUuidAsync(winrt::guid characteristicUuid, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacteristicsForUuidWithCacheModeAsync(winrt::guid characteristicUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetIncludedServicesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetIncludedServicesWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetIncludedServicesForUuidAsync(winrt::guid serviceUuid, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetIncludedServicesForUuidWithCacheModeAsync(winrt::guid serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorFromUuid(winrt::guid serviceUuid, void** selector) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorFromShortId(uint16_t serviceShortId, void** selector) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertShortIdToUuid(uint16_t shortId, winrt::guid* serviceUuid) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromIdWithSharingModeAsync(void* deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode sharingMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceId(void* bluetoothDeviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdWithCacheMode(void* bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdAndUuid(void* bluetoothDeviceId, winrt::guid serviceUuid, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceIdAndUuidWithCacheMode(void* bluetoothDeviceId, winrt::guid serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Services(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StaticValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDescriptorAsync(winrt::guid descriptorUuid, void* parameters, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Descriptors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubscribedClients(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_SubscribedClientsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SubscribedClientsChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReadRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReadRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_WriteRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WriteRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyValueAsync(void* value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyValueForSubscribedClientAsync(void* value, void* subscribedClient, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_StaticValue(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StaticValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UserDescription(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserDescription(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationFormats(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Characteristic(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StaticValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReadRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReadRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_WriteRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_WriteRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_StaticValue(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StaticValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Descriptor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCharacteristicAsync(winrt::guid characteristicUuid, void* parameters, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Characteristics(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FormatType(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Exponent(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Unit(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Namespace(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(uint16_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BluetoothSigAssignedNumbers(uint8_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Boolean(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bit2(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nibble(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt8(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt12(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt16(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt24(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt32(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt48(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt64(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UInt128(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt8(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt12(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt16(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt24(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt32(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt48(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt64(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SInt128(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Float32(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Float64(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SFloat(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Float(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DUInt16(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Utf8(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Utf16(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Struct(uint8_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InvalidHandle(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadNotPermitted(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteNotPermitted(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InvalidPdu(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsufficientAuthentication(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestNotSupported(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InvalidOffset(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsufficientAuthorization(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrepareQueueFull(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttributeNotFound(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttributeNotLong(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsufficientEncryptionKeySize(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InvalidAttributeValueLength(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnlikelyError(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsufficientEncryption(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UnsupportedGroupType(uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsufficientResources(uint8_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClientCharacteristicConfigurationDescriptor(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Offset(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Length(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL RespondWithValue(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL RespondWithProtocolError(uint8_t protocolError) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetRequestAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL WriteValue(void* characteristic, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL CommitAsync(void** asyncOp) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CommitWithResultAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Service(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdvertisementStatus(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AdvertisementStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AdvertisementStatusChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL StartAdvertising() noexcept = 0;
    virtual int32_t WINRT_CALL StartAdvertisingWithParameters(void* parameters) noexcept = 0;
    virtual int32_t WINRT_CALL StopAdvertising() noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_IsConnectable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConnectable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDiscoverable(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDiscoverable(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_ServiceData(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServiceProvider(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAsync(winrt::guid serviceUuid, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Battery(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BloodPressure(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingSpeedAndCadence(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GenericAccess(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GenericAttribute(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Glucose(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HealthThermometer(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HeartRate(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RunningSpeedAndCadence(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AlertNotification(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentTime(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CyclingPower(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInformation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HumanInterfaceDevice(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImmediateAlert(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinkLoss(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LocationAndNavigation(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NextDstChange(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhoneAlertStatus(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReferenceTimeUpdate(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScanParameters(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TxPower(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanMaintainConnection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaintainConnection(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaintainConnection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPduSize(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SessionStatus(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_MaxPduSizeChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MaxPduSizeChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SessionStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SessionStatusChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromDeviceIdAsync(void* deviceId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxNotificationSize(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_MaxNotificationSizeChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MaxNotificationSizeChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CharacteristicValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* timestamp) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Offset(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Option(Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Respond() noexcept = 0;
    virtual int32_t WINRT_CALL RespondWithProtocolError(uint8_t protocolError) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetRequestAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtocolError(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> GetDescriptors(winrt::guid const& descriptorUuid) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties CharacteristicProperties() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ProtectionLevel() const;
    void ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    hstring UserDescription() const;
    winrt::guid Uuid() const;
    uint16_t AttributeHandle() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> PresentationFormats() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> ReadValueAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> ReadValueAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> WriteValueAsync(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> WriteValueAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const& writeOption) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadClientCharacteristicConfigurationDescriptorResult> ReadClientCharacteristicConfigurationDescriptorAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> WriteClientCharacteristicConfigurationDescriptorAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const& clientCharacteristicConfigurationDescriptorValue) const;
    winrt::event_token ValueChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const& valueChangedHandler) const;
    using ValueChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic>::remove_ValueChanged>;
    ValueChanged_revoker ValueChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> const& valueChangedHandler) const;
    void ValueChanged(winrt::event_token const& valueChangedEventCookie) const noexcept;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic2
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService Service() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> GetAllDescriptors() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> GetDescriptorsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> GetDescriptorsAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> GetDescriptorsForUuidAsync(winrt::guid const& descriptorUuid) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptorsResult> GetDescriptorsForUuidAsync(winrt::guid const& descriptorUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption const& writeOption) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> WriteClientCharacteristicConfigurationDescriptorWithResultAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue const& clientCharacteristicConfigurationDescriptorValue) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristic3> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristic3<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicStatics
{
    winrt::guid ConvertShortIdToUuid(uint16_t shortId) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics
{
    winrt::guid BatteryLevel() const;
    winrt::guid BloodPressureFeature() const;
    winrt::guid BloodPressureMeasurement() const;
    winrt::guid BodySensorLocation() const;
    winrt::guid CscFeature() const;
    winrt::guid CscMeasurement() const;
    winrt::guid GlucoseFeature() const;
    winrt::guid GlucoseMeasurement() const;
    winrt::guid GlucoseMeasurementContext() const;
    winrt::guid HeartRateControlPoint() const;
    winrt::guid HeartRateMeasurement() const;
    winrt::guid IntermediateCuffPressure() const;
    winrt::guid IntermediateTemperature() const;
    winrt::guid MeasurementInterval() const;
    winrt::guid RecordAccessControlPoint() const;
    winrt::guid RscFeature() const;
    winrt::guid RscMeasurement() const;
    winrt::guid SCControlPoint() const;
    winrt::guid SensorLocation() const;
    winrt::guid TemperatureMeasurement() const;
    winrt::guid TemperatureType() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2
{
    winrt::guid AlertCategoryId() const;
    winrt::guid AlertCategoryIdBitMask() const;
    winrt::guid AlertLevel() const;
    winrt::guid AlertNotificationControlPoint() const;
    winrt::guid AlertStatus() const;
    winrt::guid GapAppearance() const;
    winrt::guid BootKeyboardInputReport() const;
    winrt::guid BootKeyboardOutputReport() const;
    winrt::guid BootMouseInputReport() const;
    winrt::guid CurrentTime() const;
    winrt::guid CyclingPowerControlPoint() const;
    winrt::guid CyclingPowerFeature() const;
    winrt::guid CyclingPowerMeasurement() const;
    winrt::guid CyclingPowerVector() const;
    winrt::guid DateTime() const;
    winrt::guid DayDateTime() const;
    winrt::guid DayOfWeek() const;
    winrt::guid GapDeviceName() const;
    winrt::guid DstOffset() const;
    winrt::guid ExactTime256() const;
    winrt::guid FirmwareRevisionString() const;
    winrt::guid HardwareRevisionString() const;
    winrt::guid HidControlPoint() const;
    winrt::guid HidInformation() const;
    winrt::guid Ieee1107320601RegulatoryCertificationDataList() const;
    winrt::guid LnControlPoint() const;
    winrt::guid LnFeature() const;
    winrt::guid LocalTimeInformation() const;
    winrt::guid LocationAndSpeed() const;
    winrt::guid ManufacturerNameString() const;
    winrt::guid ModelNumberString() const;
    winrt::guid Navigation() const;
    winrt::guid NewAlert() const;
    winrt::guid GapPeripheralPreferredConnectionParameters() const;
    winrt::guid GapPeripheralPrivacyFlag() const;
    winrt::guid PnpId() const;
    winrt::guid PositionQuality() const;
    winrt::guid ProtocolMode() const;
    winrt::guid GapReconnectionAddress() const;
    winrt::guid ReferenceTimeInformation() const;
    winrt::guid Report() const;
    winrt::guid ReportMap() const;
    winrt::guid RingerControlPoint() const;
    winrt::guid RingerSetting() const;
    winrt::guid ScanIntervalWindow() const;
    winrt::guid ScanRefresh() const;
    winrt::guid SerialNumberString() const;
    winrt::guid GattServiceChanged() const;
    winrt::guid SoftwareRevisionString() const;
    winrt::guid SupportedNewAlertCategory() const;
    winrt::guid SupportUnreadAlertCategory() const;
    winrt::guid SystemId() const;
    winrt::guid TimeAccuracy() const;
    winrt::guid TimeSource() const;
    winrt::guid TimeUpdateControlPoint() const;
    winrt::guid TimeUpdateState() const;
    winrt::guid TimeWithDst() const;
    winrt::guid TimeZone() const;
    winrt::guid TxPowerLevel() const;
    winrt::guid UnreadAlertStatus() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicUuidsStatics2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicUuidsStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicsResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> Characteristics() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattCharacteristicsResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattCharacteristicsResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient SubscribedClient() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult2
{
    uint16_t BytesSent() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattClientNotificationResult2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattClientNotificationResult2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ProtectionLevel() const;
    void ProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    winrt::guid Uuid() const;
    uint16_t AttributeHandle() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> ReadValueAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadResult> ReadValueAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> WriteValueAsync(Windows::Storage::Streams::IBuffer const& value) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor2
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> WriteValueWithResultAsync(Windows::Storage::Streams::IBuffer const& value) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptor2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptor2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorStatics
{
    winrt::guid ConvertShortIdToUuid(uint16_t shortId) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics
{
    winrt::guid CharacteristicAggregateFormat() const;
    winrt::guid CharacteristicExtendedProperties() const;
    winrt::guid CharacteristicPresentationFormat() const;
    winrt::guid CharacteristicUserDescription() const;
    winrt::guid ClientCharacteristicConfiguration() const;
    winrt::guid ServerCharacteristicConfiguration() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorUuidsStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorUuidsStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorsResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDescriptor> Descriptors() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDescriptorsResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDescriptorsResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> GetCharacteristics(winrt::guid const& characteristicUuid) const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> GetIncludedServices(winrt::guid const& serviceUuid) const;
    hstring DeviceId() const;
    winrt::guid Uuid() const;
    uint16_t AttributeHandle() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2
{
    Windows::Devices::Bluetooth::BluetoothLEDevice Device() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> ParentServices() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic> GetAllCharacteristics() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> GetAllIncludedServices() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3
{
    Windows::Devices::Enumeration::DeviceAccessInformation DeviceAccessInformation() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession Session() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode SharingMode() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> RequestAccessAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattOpenStatus> OpenAsync(Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> GetCharacteristicsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> GetCharacteristicsAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> GetCharacteristicsForUuidAsync(winrt::guid const& characteristicUuid) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult> GetCharacteristicsForUuidAsync(winrt::guid const& characteristicUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> GetIncludedServicesAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> GetIncludedServicesAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> GetIncludedServicesForUuidAsync(winrt::guid const& serviceUuid) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> GetIncludedServicesForUuidAsync(winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceService3> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceService3<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelectorFromUuid(winrt::guid const& serviceUuid) const;
    hstring GetDeviceSelectorFromShortId(uint16_t serviceShortId) const;
    winrt::guid ConvertShortIdToUuid(uint16_t shortId) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> FromIdAsync(param::hstring const& deviceId, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSharingMode const& sharingMode) const;
    hstring GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId) const;
    hstring GetDeviceSelectorForBluetoothDeviceId(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    hstring GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid) const;
    hstring GetDeviceSelectorForBluetoothDeviceIdAndUuid(Windows::Devices::Bluetooth::BluetoothDeviceId const& bluetoothDeviceId, winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServiceStatics2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServiceStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServicesResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> Services() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattDeviceServicesResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattDeviceServicesResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic
{
    winrt::guid Uuid() const;
    Windows::Storage::Streams::IBuffer StaticValue() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties CharacteristicProperties() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ReadProtectionLevel() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel WriteProtectionLevel() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorResult> CreateDescriptorAsync(winrt::guid const& descriptorUuid, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptorParameters const& parameters) const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor> Descriptors() const;
    hstring UserDescription() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> PresentationFormats() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient> SubscribedClients() const;
    winrt::event_token SubscribedClientsChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const& handler) const;
    using SubscribedClientsChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>::remove_SubscribedClientsChanged>;
    SubscribedClientsChanged_revoker SubscribedClientsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Foundation::IInspectable> const& handler) const;
    void SubscribedClientsChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token ReadRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const;
    using ReadRequested_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>::remove_ReadRequested>;
    ReadRequested_revoker ReadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const;
    void ReadRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token WriteRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const;
    using WriteRequested_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic>::remove_WriteRequested>;
    WriteRequested_revoker WriteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const;
    void WriteRequested(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult>> NotifyValueAsync(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientNotificationResult> NotifyValueAsync(Windows::Storage::Streams::IBuffer const& value, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient const& subscribedClient) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristic> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristic<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters
{
    void StaticValue(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Storage::Streams::IBuffer StaticValue() const;
    void CharacteristicProperties(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties const& value) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicProperties CharacteristicProperties() const;
    void ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ReadProtectionLevel() const;
    void WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel WriteProtectionLevel() const;
    void UserDescription(param::hstring const& value) const;
    hstring UserDescription() const;
    Windows::Foundation::Collections::IVector<Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat> PresentationFormats() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicParameters> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicParameters<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic Characteristic() const;
    Windows::Devices::Bluetooth::BluetoothError Error() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalCharacteristicResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalCharacteristicResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor
{
    winrt::guid Uuid() const;
    Windows::Storage::Streams::IBuffer StaticValue() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ReadProtectionLevel() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel WriteProtectionLevel() const;
    winrt::event_token ReadRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const;
    using ReadRequested_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>::remove_ReadRequested>;
    ReadRequested_revoker ReadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequestedEventArgs> const& handler) const;
    void ReadRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token WriteRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const;
    using WriteRequested_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor>::remove_WriteRequested>;
    WriteRequested_revoker WriteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor, Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequestedEventArgs> const& handler) const;
    void WriteRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptor> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptor<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters
{
    void StaticValue(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Storage::Streams::IBuffer StaticValue() const;
    void ReadProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel ReadProtectionLevel() const;
    void WriteProtectionLevel(Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel const& value) const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattProtectionLevel WriteProtectionLevel() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorParameters> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorParameters<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalDescriptor Descriptor() const;
    Windows::Devices::Bluetooth::BluetoothError Error() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalDescriptorResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalDescriptorResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalService
{
    winrt::guid Uuid() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicResult> CreateCharacteristicAsync(winrt::guid const& characteristicUuid, Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristicParameters const& parameters) const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalCharacteristic> Characteristics() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattLocalService> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattLocalService<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat
{
    uint8_t FormatType() const;
    int32_t Exponent() const;
    uint16_t Unit() const;
    uint8_t Namespace() const;
    uint16_t Description() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormat> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormat<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics
{
    uint8_t BluetoothSigAssignedNumbers() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics2
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattPresentationFormat FromParts(uint8_t formatType, int32_t exponent, uint16_t unit, uint8_t namespaceId, uint16_t description) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatStatics2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics
{
    uint8_t Boolean() const;
    uint8_t Bit2() const;
    uint8_t Nibble() const;
    uint8_t UInt8() const;
    uint8_t UInt12() const;
    uint8_t UInt16() const;
    uint8_t UInt24() const;
    uint8_t UInt32() const;
    uint8_t UInt48() const;
    uint8_t UInt64() const;
    uint8_t UInt128() const;
    uint8_t SInt8() const;
    uint8_t SInt12() const;
    uint8_t SInt16() const;
    uint8_t SInt24() const;
    uint8_t SInt32() const;
    uint8_t SInt48() const;
    uint8_t SInt64() const;
    uint8_t SInt128() const;
    uint8_t Float32() const;
    uint8_t Float64() const;
    uint8_t SFloat() const;
    uint8_t Float() const;
    uint8_t DUInt16() const;
    uint8_t Utf8() const;
    uint8_t Utf16() const;
    uint8_t Struct() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattPresentationFormatTypesStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattPresentationFormatTypesStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics
{
    uint8_t InvalidHandle() const;
    uint8_t ReadNotPermitted() const;
    uint8_t WriteNotPermitted() const;
    uint8_t InvalidPdu() const;
    uint8_t InsufficientAuthentication() const;
    uint8_t RequestNotSupported() const;
    uint8_t InvalidOffset() const;
    uint8_t InsufficientAuthorization() const;
    uint8_t PrepareQueueFull() const;
    uint8_t AttributeNotFound() const;
    uint8_t AttributeNotLong() const;
    uint8_t InsufficientEncryptionKeySize() const;
    uint8_t InvalidAttributeValueLength() const;
    uint8_t UnlikelyError() const;
    uint8_t InsufficientEncryption() const;
    uint8_t UnsupportedGroupType() const;
    uint8_t InsufficientResources() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattProtocolErrorStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattProtocolErrorStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue ClientCharacteristicConfigurationDescriptor() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult2
{
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadClientCharacteristicConfigurationDescriptorResult2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadClientCharacteristicConfigurationDescriptorResult2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest
{
    uint32_t Offset() const;
    uint32_t Length() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState State() const;
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
    void RespondWithValue(Windows::Storage::Streams::IBuffer const& value) const;
    void RespondWithProtocolError(uint8_t protocolError) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequest> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequest<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequestedEventArgs
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession Session() const;
    Windows::Foundation::Deferral GetDeferral() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattReadRequest> GetRequestAsync() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Storage::Streams::IBuffer Value() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult2
{
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReadResult2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReadResult2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction
{
    void WriteValue(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic const& characteristic, Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus> CommitAsync() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction2
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteResult> CommitWithResultAsync() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattReliableWriteTransaction2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattReliableWriteTransaction2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattRequestStateChangedEventArgs
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState State() const;
    Windows::Devices::Bluetooth::BluetoothError Error() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattRequestStateChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattRequestStateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService Service() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus AdvertisementStatus() const;
    winrt::event_token AdvertisementStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const& handler) const;
    using AdvertisementStatusChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider>::remove_AdvertisementStatusChanged>;
    AdvertisementStatusChanged_revoker AdvertisementStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider, Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatusChangedEventArgs> const& handler) const;
    void AdvertisementStatusChanged(winrt::event_token const& token) const noexcept;
    void StartAdvertising() const;
    void StartAdvertising(Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisingParameters const& parameters) const;
    void StopAdvertising() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProvider> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProvider<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisementStatusChangedEventArgs
{
    Windows::Devices::Bluetooth::BluetoothError Error() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderAdvertisementStatus Status() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisementStatusChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisementStatusChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters
{
    void IsConnectable(bool value) const;
    bool IsConnectable() const;
    void IsDiscoverable(bool value) const;
    bool IsDiscoverable() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters2
{
    void ServiceData(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Storage::Streams::IBuffer ServiceData() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderAdvertisingParameters2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderAdvertisingParameters2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderResult
{
    Windows::Devices::Bluetooth::BluetoothError Error() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProvider ServiceProvider() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderResult<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattServiceProviderResult> CreateAsync(winrt::guid const& serviceUuid) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceProviderStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceProviderStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics
{
    winrt::guid Battery() const;
    winrt::guid BloodPressure() const;
    winrt::guid CyclingSpeedAndCadence() const;
    winrt::guid GenericAccess() const;
    winrt::guid GenericAttribute() const;
    winrt::guid Glucose() const;
    winrt::guid HealthThermometer() const;
    winrt::guid HeartRate() const;
    winrt::guid RunningSpeedAndCadence() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2
{
    winrt::guid AlertNotification() const;
    winrt::guid CurrentTime() const;
    winrt::guid CyclingPower() const;
    winrt::guid DeviceInformation() const;
    winrt::guid HumanInterfaceDevice() const;
    winrt::guid ImmediateAlert() const;
    winrt::guid LinkLoss() const;
    winrt::guid LocationAndNavigation() const;
    winrt::guid NextDstChange() const;
    winrt::guid PhoneAlertStatus() const;
    winrt::guid ReferenceTimeUpdate() const;
    winrt::guid ScanParameters() const;
    winrt::guid TxPower() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattServiceUuidsStatics2> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattServiceUuidsStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession
{
    Windows::Devices::Bluetooth::BluetoothDeviceId DeviceId() const;
    bool CanMaintainConnection() const;
    void MaintainConnection(bool value) const;
    bool MaintainConnection() const;
    uint16_t MaxPduSize() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus SessionStatus() const;
    winrt::event_token MaxPduSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const& handler) const;
    using MaxPduSizeChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>::remove_MaxPduSizeChanged>;
    MaxPduSizeChanged_revoker MaxPduSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Foundation::IInspectable> const& handler) const;
    void MaxPduSizeChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SessionStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const& handler) const;
    using SessionStatusChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession>::remove_SessionStatusChanged>;
    SessionStatusChanged_revoker SessionStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession, Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatusChangedEventArgs> const& handler) const;
    void SessionStatusChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSession> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSession<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession> FromDeviceIdAsync(Windows::Devices::Bluetooth::BluetoothDeviceId const& deviceId) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatics> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatusChangedEventArgs
{
    Windows::Devices::Bluetooth::BluetoothError Error() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSessionStatus Status() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSessionStatusChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSessionStatusChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession Session() const;
    uint16_t MaxNotificationSize() const;
    winrt::event_token MaxNotificationSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const& handler) const;
    using MaxNotificationSizeChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient>::remove_MaxNotificationSizeChanged>;
    MaxNotificationSizeChanged_revoker MaxNotificationSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattSubscribedClient, Windows::Foundation::IInspectable> const& handler) const;
    void MaxNotificationSizeChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattSubscribedClient> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattSubscribedClient<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattValueChangedEventArgs
{
    Windows::Storage::Streams::IBuffer CharacteristicValue() const;
    Windows::Foundation::DateTime Timestamp() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattValueChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattValueChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest
{
    Windows::Storage::Streams::IBuffer Value() const;
    uint32_t Offset() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteOption Option() const;
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestState State() const;
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest, &impl::abi_t<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest, Windows::Devices::Bluetooth::GenericAttributeProfile::GattRequestStateChangedEventArgs> const& handler) const;
    void StateChanged(winrt::event_token const& token) const noexcept;
    void Respond() const;
    void RespondWithProtocolError(uint8_t protocolError) const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequest> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequest<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequestedEventArgs
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattSession Session() const;
    Windows::Foundation::Deferral GetDeferral() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattWriteRequest> GetRequestAsync() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteResult
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCommunicationStatus Status() const;
    Windows::Foundation::IReference<uint8_t> ProtocolError() const;
};
template <> struct consume<Windows::Devices::Bluetooth::GenericAttributeProfile::IGattWriteResult> { template <typename D> using type = consume_Windows_Devices_Bluetooth_GenericAttributeProfile_IGattWriteResult<D>; };

}
