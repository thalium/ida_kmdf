// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Background {

struct DeviceWatcherTrigger;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

struct PasswordCredential;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

enum class InputStreamOptions : unsigned;
struct IBuffer;
struct IInputStream;
struct IOutputStream;
struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

enum class Placement;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

enum class DeviceAccessStatus : int32_t
{
    Unspecified = 0,
    Allowed = 1,
    DeniedByUser = 2,
    DeniedBySystem = 3,
};

enum class DeviceClass : int32_t
{
    All = 0,
    AudioCapture = 1,
    AudioRender = 2,
    PortableStorageDevice = 3,
    VideoCapture = 4,
    ImageScanner = 5,
    Location = 6,
};

enum class DeviceInformationKind : int32_t
{
    Unknown = 0,
    DeviceInterface = 1,
    DeviceContainer = 2,
    Device = 3,
    DeviceInterfaceClass = 4,
    AssociationEndpoint = 5,
    AssociationEndpointContainer = 6,
    AssociationEndpointService = 7,
    DevicePanel = 8,
};

enum class DevicePairingKinds : uint32_t
{
    None = 0x0,
    ConfirmOnly = 0x1,
    DisplayPin = 0x2,
    ProvidePin = 0x4,
    ConfirmPinMatch = 0x8,
    ProvidePasswordCredential = 0x10,
};

enum class DevicePairingProtectionLevel : int32_t
{
    Default = 0,
    None = 1,
    Encryption = 2,
    EncryptionAndAuthentication = 3,
};

enum class DevicePairingResultStatus : int32_t
{
    Paired = 0,
    NotReadyToPair = 1,
    NotPaired = 2,
    AlreadyPaired = 3,
    ConnectionRejected = 4,
    TooManyConnections = 5,
    HardwareFailure = 6,
    AuthenticationTimeout = 7,
    AuthenticationNotAllowed = 8,
    AuthenticationFailure = 9,
    NoSupportedProfiles = 10,
    ProtectionLevelCouldNotBeMet = 11,
    AccessDenied = 12,
    InvalidCeremonyData = 13,
    PairingCanceled = 14,
    OperationAlreadyInProgress = 15,
    RequiredHandlerNotRegistered = 16,
    RejectedByHandler = 17,
    RemoteDeviceHasAssociation = 18,
    Failed = 19,
};

enum class DevicePickerDisplayStatusOptions : uint32_t
{
    None = 0x0,
    ShowProgress = 0x1,
    ShowDisconnectButton = 0x2,
    ShowRetryButton = 0x4,
};

enum class DeviceUnpairingResultStatus : int32_t
{
    Unpaired = 0,
    AlreadyUnpaired = 1,
    OperationAlreadyInProgress = 2,
    AccessDenied = 3,
    Failed = 4,
};

enum class DeviceWatcherEventKind : int32_t
{
    Add = 0,
    Update = 1,
    Remove = 2,
};

enum class DeviceWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopping = 3,
    Stopped = 4,
    Aborted = 5,
};

enum class Panel : int32_t
{
    Unknown = 0,
    Front = 1,
    Back = 2,
    Top = 3,
    Bottom = 4,
    Left = 5,
    Right = 6,
};

struct IDeviceAccessChangedEventArgs;
struct IDeviceAccessChangedEventArgs2;
struct IDeviceAccessInformation;
struct IDeviceAccessInformationStatics;
struct IDeviceConnectionChangeTriggerDetails;
struct IDeviceDisconnectButtonClickedEventArgs;
struct IDeviceInformation;
struct IDeviceInformation2;
struct IDeviceInformationCustomPairing;
struct IDeviceInformationPairing;
struct IDeviceInformationPairing2;
struct IDeviceInformationPairingStatics;
struct IDeviceInformationPairingStatics2;
struct IDeviceInformationStatics;
struct IDeviceInformationStatics2;
struct IDeviceInformationUpdate;
struct IDeviceInformationUpdate2;
struct IDevicePairingRequestedEventArgs;
struct IDevicePairingRequestedEventArgs2;
struct IDevicePairingResult;
struct IDevicePairingSettings;
struct IDevicePicker;
struct IDevicePickerAppearance;
struct IDevicePickerFilter;
struct IDeviceSelectedEventArgs;
struct IDeviceUnpairingResult;
struct IDeviceWatcher;
struct IDeviceWatcher2;
struct IDeviceWatcherEvent;
struct IDeviceWatcherTriggerDetails;
struct IEnclosureLocation;
struct IEnclosureLocation2;
struct DeviceAccessChangedEventArgs;
struct DeviceAccessInformation;
struct DeviceConnectionChangeTriggerDetails;
struct DeviceDisconnectButtonClickedEventArgs;
struct DeviceInformation;
struct DeviceInformationCollection;
struct DeviceInformationCustomPairing;
struct DeviceInformationPairing;
struct DeviceInformationUpdate;
struct DevicePairingRequestedEventArgs;
struct DevicePairingResult;
struct DevicePicker;
struct DevicePickerAppearance;
struct DevicePickerFilter;
struct DeviceSelectedEventArgs;
struct DeviceThumbnail;
struct DeviceUnpairingResult;
struct DeviceWatcher;
struct DeviceWatcherEvent;
struct DeviceWatcherTriggerDetails;
struct EnclosureLocation;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Devices::Enumeration::DevicePairingKinds> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions> : std::true_type {};
template <> struct category<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceAccessInformation>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceAccessInformationStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformation>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformation2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationCustomPairing>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationPairing>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationPairing2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationPairingStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationStatics2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationUpdate>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceInformationUpdate2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePairingResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePairingSettings>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePicker>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePickerAppearance>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDevicePickerFilter>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceSelectedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceUnpairingResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceWatcher>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceWatcher2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceWatcherEvent>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IEnclosureLocation>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::IEnclosureLocation2>{ using type = interface_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceAccessChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceAccessInformation>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformation>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformationCollection>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformationCustomPairing>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformationPairing>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformationUpdate>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePairingRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePairingResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePicker>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePickerAppearance>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePickerFilter>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceSelectedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceThumbnail>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceUnpairingResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceWatcher>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceWatcherEvent>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceWatcherTriggerDetails>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::EnclosureLocation>{ using type = class_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceAccessStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceClass>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceInformationKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePairingKinds>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePairingProtectionLevel>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePairingResultStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceUnpairingResultStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceWatcherEventKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::DeviceWatcherStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Enumeration::Panel>{ using type = enum_category; };
template <> struct name<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceAccessChangedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceAccessChangedEventArgs2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceAccessInformation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceAccessInformation" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceAccessInformationStatics>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceAccessInformationStatics" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceConnectionChangeTriggerDetails" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceDisconnectButtonClickedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformation" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformation2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformation2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationCustomPairing>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationCustomPairing" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationPairing>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationPairing" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationPairing2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationPairing2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationPairingStatics>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationPairingStatics" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationPairingStatics2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationStatics>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationStatics" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationStatics2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationStatics2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationUpdate>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationUpdate" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceInformationUpdate2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceInformationUpdate2" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePairingRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePairingRequestedEventArgs2" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePairingResult>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePairingResult" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePairingSettings>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePairingSettings" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePicker>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePicker" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePickerAppearance>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePickerAppearance" }; };
template <> struct name<Windows::Devices::Enumeration::IDevicePickerFilter>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDevicePickerFilter" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceSelectedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceUnpairingResult>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceUnpairingResult" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceWatcher>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceWatcher" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceWatcher2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceWatcher2" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceWatcherEvent>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceWatcherEvent" }; };
template <> struct name<Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IDeviceWatcherTriggerDetails" }; };
template <> struct name<Windows::Devices::Enumeration::IEnclosureLocation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IEnclosureLocation" }; };
template <> struct name<Windows::Devices::Enumeration::IEnclosureLocation2>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.IEnclosureLocation2" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceAccessChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceAccessChangedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceAccessInformation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceAccessInformation" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceConnectionChangeTriggerDetails" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceDisconnectButtonClickedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformation" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformationCollection>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformationCollection" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformationCustomPairing>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformationCustomPairing" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformationPairing>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformationPairing" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformationUpdate>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformationUpdate" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePairingRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePairingRequestedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePairingResult>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePairingResult" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePicker>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePicker" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePickerAppearance>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePickerAppearance" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePickerFilter>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePickerFilter" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceSelectedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceSelectedEventArgs" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceThumbnail>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceThumbnail" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceUnpairingResult>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceUnpairingResult" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceWatcher>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceWatcher" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceWatcherEvent>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceWatcherEvent" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceWatcherTriggerDetails>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceWatcherTriggerDetails" }; };
template <> struct name<Windows::Devices::Enumeration::EnclosureLocation>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.EnclosureLocation" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceAccessStatus>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceAccessStatus" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceClass>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceClass" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceInformationKind>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceInformationKind" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePairingKinds>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePairingKinds" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePairingProtectionLevel>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePairingProtectionLevel" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePairingResultStatus>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePairingResultStatus" }; };
template <> struct name<Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DevicePickerDisplayStatusOptions" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceUnpairingResultStatus>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceUnpairingResultStatus" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceWatcherEventKind>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceWatcherEventKind" }; };
template <> struct name<Windows::Devices::Enumeration::DeviceWatcherStatus>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.DeviceWatcherStatus" }; };
template <> struct name<Windows::Devices::Enumeration::Panel>{ static constexpr auto & value{ L"Windows.Devices.Enumeration.Panel" }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>{ static constexpr guid value{ 0xDEDA0BCC,0x4F9D,0x4F58,{ 0x9D,0xBA,0xA9,0xBC,0x80,0x04,0x08,0xD5 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>{ static constexpr guid value{ 0x82523262,0x934B,0x4B30,{ 0xA1,0x78,0xAD,0xC3,0x9F,0x2F,0x2B,0xE3 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceAccessInformation>{ static constexpr guid value{ 0x0BAA9A73,0x6DE5,0x4915,{ 0x8D,0xDD,0x9A,0x05,0x54,0xA6,0xF5,0x45 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceAccessInformationStatics>{ static constexpr guid value{ 0x574BD3D3,0x5F30,0x45CD,{ 0x8A,0x94,0x72,0x4F,0xE5,0x97,0x30,0x84 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>{ static constexpr guid value{ 0xB8578C0C,0xBBC1,0x484B,{ 0xBF,0xFA,0x7B,0x31,0xDC,0xC2,0x00,0xB2 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>{ static constexpr guid value{ 0x8E44B56D,0xF902,0x4A00,{ 0xB5,0x36,0xF3,0x79,0x92,0xE6,0xA2,0xA7 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformation>{ static constexpr guid value{ 0xABA0FB95,0x4398,0x489D,{ 0x8E,0x44,0xE6,0x13,0x09,0x27,0x01,0x1F } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformation2>{ static constexpr guid value{ 0xF156A638,0x7997,0x48D9,{ 0xA1,0x0C,0x26,0x9D,0x46,0x53,0x3F,0x48 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationCustomPairing>{ static constexpr guid value{ 0x85138C02,0x4EE6,0x4914,{ 0x83,0x70,0x10,0x7A,0x39,0x14,0x4C,0x0E } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationPairing>{ static constexpr guid value{ 0x2C4769F5,0xF684,0x40D5,{ 0x84,0x69,0xE8,0xDB,0xAA,0xB7,0x04,0x85 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationPairing2>{ static constexpr guid value{ 0xF68612FD,0x0AEE,0x4328,{ 0x85,0xCC,0x1C,0x74,0x2B,0xB1,0x79,0x0D } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationPairingStatics>{ static constexpr guid value{ 0xE915C408,0x36D4,0x49A1,{ 0xBF,0x13,0x51,0x41,0x73,0x79,0x9B,0x6B } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>{ static constexpr guid value{ 0x04DE5372,0xB7B7,0x476B,{ 0xA7,0x4F,0xC5,0x83,0x6A,0x70,0x4D,0x98 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationStatics>{ static constexpr guid value{ 0xC17F100E,0x3A46,0x4A78,{ 0x80,0x13,0x76,0x9D,0xC9,0xB9,0x73,0x90 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationStatics2>{ static constexpr guid value{ 0x493B4F34,0xA84F,0x45FD,{ 0x91,0x67,0x15,0xD1,0xCB,0x1B,0xD1,0xF9 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationUpdate>{ static constexpr guid value{ 0x8F315305,0xD972,0x44B7,{ 0xA3,0x7E,0x9E,0x82,0x2C,0x78,0x21,0x3B } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceInformationUpdate2>{ static constexpr guid value{ 0x5D9D148C,0xA873,0x485E,{ 0xBA,0xA6,0xAA,0x62,0x07,0x88,0xE3,0xCC } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>{ static constexpr guid value{ 0xF717FC56,0xDE6B,0x487F,{ 0x83,0x76,0x01,0x80,0xAC,0xA6,0x99,0x63 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>{ static constexpr guid value{ 0xC83752D9,0xE4D3,0x4DB0,{ 0xA3,0x60,0xA1,0x05,0xE4,0x37,0xDB,0xDC } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePairingResult>{ static constexpr guid value{ 0x072B02BF,0xDD95,0x4025,{ 0x9B,0x37,0xDE,0x51,0xAD,0xBA,0x37,0xB7 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePairingSettings>{ static constexpr guid value{ 0x482CB27C,0x83BB,0x420E,{ 0xBE,0x51,0x66,0x02,0xB2,0x22,0xDE,0x54 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePicker>{ static constexpr guid value{ 0x84997AA2,0x034A,0x4440,{ 0x88,0x13,0x7D,0x0B,0xD4,0x79,0xBF,0x5A } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePickerAppearance>{ static constexpr guid value{ 0xE69A12C6,0xE627,0x4ED8,{ 0x9B,0x6C,0x46,0x0A,0xF4,0x45,0xE5,0x6D } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDevicePickerFilter>{ static constexpr guid value{ 0x91DB92A2,0x57CB,0x48F1,{ 0x9B,0x59,0xA5,0x9B,0x7A,0x1F,0x02,0xA2 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceSelectedEventArgs>{ static constexpr guid value{ 0x269EDADE,0x1D2F,0x4940,{ 0x84,0x02,0x41,0x56,0xB8,0x1D,0x3C,0x77 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceUnpairingResult>{ static constexpr guid value{ 0x66F44AD3,0x79D9,0x444B,{ 0x92,0xCF,0xA9,0x2E,0xF7,0x25,0x71,0xC7 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceWatcher>{ static constexpr guid value{ 0xC9EAB97D,0x8F6B,0x4F96,{ 0xA9,0xF4,0xAB,0xC8,0x14,0xE2,0x22,0x71 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceWatcher2>{ static constexpr guid value{ 0xFF08456E,0xED14,0x49E9,{ 0x9A,0x69,0x81,0x17,0xC5,0x4A,0xE9,0x71 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceWatcherEvent>{ static constexpr guid value{ 0x74AA9C0B,0x1DBD,0x47FD,{ 0xB6,0x35,0x3C,0xC5,0x56,0xD0,0xFF,0x8B } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>{ static constexpr guid value{ 0x38808119,0x4CB7,0x4E57,{ 0xA5,0x6D,0x77,0x6D,0x07,0xCB,0xFE,0xF9 } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IEnclosureLocation>{ static constexpr guid value{ 0x42340A27,0x5810,0x459C,{ 0xAA,0xBB,0xC6,0x5E,0x1F,0x81,0x3E,0xCF } }; };
template <> struct guid_storage<Windows::Devices::Enumeration::IEnclosureLocation2>{ static constexpr guid value{ 0x2885995B,0xE07D,0x485D,{ 0x8A,0x9E,0xBD,0xF2,0x9A,0xEF,0x4F,0x66 } }; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceAccessChangedEventArgs>{ using type = Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceAccessInformation>{ using type = Windows::Devices::Enumeration::IDeviceAccessInformation; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceConnectionChangeTriggerDetails>{ using type = Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs>{ using type = Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceInformation>{ using type = Windows::Devices::Enumeration::IDeviceInformation; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceInformationCollection>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceInformation>; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceInformationCustomPairing>{ using type = Windows::Devices::Enumeration::IDeviceInformationCustomPairing; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceInformationPairing>{ using type = Windows::Devices::Enumeration::IDeviceInformationPairing; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceInformationUpdate>{ using type = Windows::Devices::Enumeration::IDeviceInformationUpdate; };
template <> struct default_interface<Windows::Devices::Enumeration::DevicePairingRequestedEventArgs>{ using type = Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs; };
template <> struct default_interface<Windows::Devices::Enumeration::DevicePairingResult>{ using type = Windows::Devices::Enumeration::IDevicePairingResult; };
template <> struct default_interface<Windows::Devices::Enumeration::DevicePicker>{ using type = Windows::Devices::Enumeration::IDevicePicker; };
template <> struct default_interface<Windows::Devices::Enumeration::DevicePickerAppearance>{ using type = Windows::Devices::Enumeration::IDevicePickerAppearance; };
template <> struct default_interface<Windows::Devices::Enumeration::DevicePickerFilter>{ using type = Windows::Devices::Enumeration::IDevicePickerFilter; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceSelectedEventArgs>{ using type = Windows::Devices::Enumeration::IDeviceSelectedEventArgs; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceThumbnail>{ using type = Windows::Storage::Streams::IRandomAccessStreamWithContentType; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceUnpairingResult>{ using type = Windows::Devices::Enumeration::IDeviceUnpairingResult; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceWatcher>{ using type = Windows::Devices::Enumeration::IDeviceWatcher; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceWatcherEvent>{ using type = Windows::Devices::Enumeration::IDeviceWatcherEvent; };
template <> struct default_interface<Windows::Devices::Enumeration::DeviceWatcherTriggerDetails>{ using type = Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails; };
template <> struct default_interface<Windows::Devices::Enumeration::EnclosureLocation>{ using type = Windows::Devices::Enumeration::IEnclosureLocation; };

template <> struct abi<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceAccessStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceAccessInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_AccessChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccessChanged(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentStatus(Windows::Devices::Enumeration::DeviceAccessStatus* status) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceAccessInformationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromId(void* deviceId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromDeviceClassId(winrt::guid deviceClassId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Device(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDefault(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EnclosureLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Update(void* updateInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GetThumbnailAsync(void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL GetGlyphThumbnailAsync(void** asyncOp) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceInformationKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pairing(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationCustomPairing>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL PairAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PairWithProtectionLevelAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PairWithProtectionLevelAndSettingsAsync(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void* devicePairingSettings, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_PairingRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PairingRequested(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationPairing>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPaired(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanPair(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL PairAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL PairWithProtectionLevelAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationPairing2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtectionLevel(Windows::Devices::Enumeration::DevicePairingProtectionLevel* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Custom(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL PairWithProtectionLevelAndSettingsAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, void* devicePairingSettings, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL UnpairAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationPairingStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryRegisterForAllInboundPairingRequests(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationPairingStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryRegisterForAllInboundPairingRequestsWithProtectionLevel(Windows::Devices::Enumeration::DevicePairingKinds pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel minProtectionLevel, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromIdAsync(void* deviceId, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromIdAsyncAdditionalProperties(void* deviceId, void* additionalProperties, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsync(void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncAqsFilter(void* aqsFilter, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcher(void** watcher) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcherDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** watcher) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcherAqsFilter(void* aqsFilter, void** watcher) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcherAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, void** watcher) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAqsFilterFromDeviceClass(Windows::Devices::Enumeration::DeviceClass deviceClass, void** aqsFilter) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromIdAsyncWithKindAndAdditionalProperties(void* deviceId, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllAsyncWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** asyncOp) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWatcherWithKindAqsFilterAndAdditionalProperties(void* aqsFilter, void* additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind kind, void** watcher) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationUpdate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceInformationUpdate2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceInformationKind* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PairingKind(Windows::Devices::Enumeration::DevicePairingKinds* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pin(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Accept() noexcept = 0;
    virtual int32_t WINRT_CALL AcceptWithPin(void* pin) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AcceptWithPasswordCredential(void* passwordCredential) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePairingResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DevicePairingResultStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtectionLevelUsed(Windows::Devices::Enumeration::DevicePairingProtectionLevel* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePairingSettings>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePicker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Filter(void** filter) noexcept = 0;
    virtual int32_t WINRT_CALL get_Appearance(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestedProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_DeviceSelected(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DeviceSelected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DisconnectButtonClicked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DisconnectButtonClicked(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DevicePickerDismissed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DevicePickerDismissed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept = 0;
    virtual int32_t WINRT_CALL ShowWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement placement) noexcept = 0;
    virtual int32_t WINRT_CALL PickSingleDeviceAsync(Windows::Foundation::Rect selection, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PickSingleDeviceAsyncWithPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement placement, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL Hide() noexcept = 0;
    virtual int32_t WINRT_CALL SetDisplayStatus(void* device, void* status, Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions options) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePickerAppearance>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccentColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AccentColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedForegroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SelectedForegroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedBackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SelectedBackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedAccentColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SelectedAccentColor(struct struct_Windows_UI_Color value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDevicePickerFilter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportedDeviceClasses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedDeviceSelectors(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceSelectedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SelectedDevice(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceUnpairingResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceUnpairingResultStatus* status) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Enumeration::DeviceWatcherStatus* status) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceWatcher2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetBackgroundTrigger(void* requestedEventKinds, void** trigger) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceWatcherEvent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::Devices::Enumeration::DeviceWatcherEventKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInformationUpdate(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceWatcherEvents(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IEnclosureLocation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InDock(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InLid(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Panel(Windows::Devices::Enumeration::Panel* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Enumeration::IEnclosureLocation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RotationAngleInDegreesClockwise(uint32_t* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs
{
    Windows::Devices::Enumeration::DeviceAccessStatus Status() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs2
{
    hstring Id() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceAccessChangedEventArgs2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceAccessChangedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceAccessInformation
{
    winrt::event_token AccessChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const;
    using AccessChanged_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceAccessInformation, &impl::abi_t<Windows::Devices::Enumeration::IDeviceAccessInformation>::remove_AccessChanged>;
    AccessChanged_revoker AccessChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceAccessInformation, Windows::Devices::Enumeration::DeviceAccessChangedEventArgs> const& handler) const;
    void AccessChanged(winrt::event_token const& cookie) const noexcept;
    Windows::Devices::Enumeration::DeviceAccessStatus CurrentStatus() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceAccessInformation> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceAccessInformation<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics
{
    Windows::Devices::Enumeration::DeviceAccessInformation CreateFromId(param::hstring const& deviceId) const;
    Windows::Devices::Enumeration::DeviceAccessInformation CreateFromDeviceClassId(winrt::guid const& deviceClassId) const;
    Windows::Devices::Enumeration::DeviceAccessInformation CreateFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceAccessInformationStatics> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceAccessInformationStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceConnectionChangeTriggerDetails
{
    hstring DeviceId() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceConnectionChangeTriggerDetails> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceConnectionChangeTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceDisconnectButtonClickedEventArgs
{
    Windows::Devices::Enumeration::DeviceInformation Device() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceDisconnectButtonClickedEventArgs> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceDisconnectButtonClickedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformation
{
    hstring Id() const;
    hstring Name() const;
    bool IsEnabled() const;
    bool IsDefault() const;
    Windows::Devices::Enumeration::EnclosureLocation EnclosureLocation() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties() const;
    void Update(Windows::Devices::Enumeration::DeviceInformationUpdate const& updateInfo) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> GetThumbnailAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceThumbnail> GetGlyphThumbnailAsync() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformation> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformation<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformation2
{
    Windows::Devices::Enumeration::DeviceInformationKind Kind() const;
    Windows::Devices::Enumeration::DeviceInformationPairing Pairing() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformation2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformation2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const;
    winrt::event_token PairingRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const;
    using PairingRequested_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceInformationCustomPairing, &impl::abi_t<Windows::Devices::Enumeration::IDeviceInformationCustomPairing>::remove_PairingRequested>;
    PairingRequested_revoker PairingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceInformationCustomPairing, Windows::Devices::Enumeration::DevicePairingRequestedEventArgs> const& handler) const;
    void PairingRequested(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationCustomPairing> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationCustomPairing<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationPairing
{
    bool IsPaired() const;
    bool CanPair() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationPairing> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationPairing<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationPairing2
{
    Windows::Devices::Enumeration::DevicePairingProtectionLevel ProtectionLevel() const;
    Windows::Devices::Enumeration::DeviceInformationCustomPairing Custom() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DevicePairingResult> PairAsync(Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel, Windows::Devices::Enumeration::IDevicePairingSettings const& devicePairingSettings) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceUnpairingResult> UnpairAsync() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationPairing2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationPairing2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics
{
    bool TryRegisterForAllInboundPairingRequests(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationPairingStatics> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics2
{
    bool TryRegisterForAllInboundPairingRequestsWithProtectionLevel(Windows::Devices::Enumeration::DevicePairingKinds const& pairingKindsSupported, Windows::Devices::Enumeration::DevicePairingProtectionLevel const& minProtectionLevel) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationPairingStatics2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationPairingStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> CreateFromIdAsync(param::hstring const& deviceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> FindAllAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> FindAllAsync(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> FindAllAsync(param::hstring const& aqsFilter) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties) const;
    Windows::Devices::Enumeration::DeviceWatcher CreateWatcher() const;
    Windows::Devices::Enumeration::DeviceWatcher CreateWatcher(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const;
    Windows::Devices::Enumeration::DeviceWatcher CreateWatcher(param::hstring const& aqsFilter) const;
    Windows::Devices::Enumeration::DeviceWatcher CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationStatics> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationStatics2
{
    hstring GetAqsFilterFromDeviceClass(Windows::Devices::Enumeration::DeviceClass const& deviceClass) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> CreateFromIdAsync(param::hstring const& deviceId, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformationCollection> FindAllAsync(param::hstring const& aqsFilter, param::async_iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const;
    Windows::Devices::Enumeration::DeviceWatcher CreateWatcher(param::hstring const& aqsFilter, param::iterable<hstring> const& additionalProperties, Windows::Devices::Enumeration::DeviceInformationKind const& kind) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationStatics2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationStatics2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationUpdate
{
    hstring Id() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationUpdate> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationUpdate<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceInformationUpdate2
{
    Windows::Devices::Enumeration::DeviceInformationKind Kind() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceInformationUpdate2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceInformationUpdate2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs
{
    Windows::Devices::Enumeration::DeviceInformation DeviceInformation() const;
    Windows::Devices::Enumeration::DevicePairingKinds PairingKind() const;
    hstring Pin() const;
    void Accept() const;
    void Accept(param::hstring const& pin) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs2
{
    void AcceptWithPasswordCredential(Windows::Security::Credentials::PasswordCredential const& passwordCredential) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePairingRequestedEventArgs2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePairingRequestedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePairingResult
{
    Windows::Devices::Enumeration::DevicePairingResultStatus Status() const;
    Windows::Devices::Enumeration::DevicePairingProtectionLevel ProtectionLevelUsed() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePairingResult> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePairingResult<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePairingSettings
{
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePairingSettings> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePairingSettings<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePicker
{
    Windows::Devices::Enumeration::DevicePickerFilter Filter() const;
    Windows::Devices::Enumeration::DevicePickerAppearance Appearance() const;
    Windows::Foundation::Collections::IVector<hstring> RequestedProperties() const;
    winrt::event_token DeviceSelected(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const;
    using DeviceSelected_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDevicePicker, &impl::abi_t<Windows::Devices::Enumeration::IDevicePicker>::remove_DeviceSelected>;
    DeviceSelected_revoker DeviceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceSelectedEventArgs> const& handler) const;
    void DeviceSelected(winrt::event_token const& token) const noexcept;
    winrt::event_token DisconnectButtonClicked(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const;
    using DisconnectButtonClicked_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDevicePicker, &impl::abi_t<Windows::Devices::Enumeration::IDevicePicker>::remove_DisconnectButtonClicked>;
    DisconnectButtonClicked_revoker DisconnectButtonClicked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Devices::Enumeration::DeviceDisconnectButtonClickedEventArgs> const& handler) const;
    void DisconnectButtonClicked(winrt::event_token const& token) const noexcept;
    winrt::event_token DevicePickerDismissed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    using DevicePickerDismissed_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDevicePicker, &impl::abi_t<Windows::Devices::Enumeration::IDevicePicker>::remove_DevicePickerDismissed>;
    DevicePickerDismissed_revoker DevicePickerDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DevicePicker, Windows::Foundation::IInspectable> const& handler) const;
    void DevicePickerDismissed(winrt::event_token const& token) const noexcept;
    void Show(Windows::Foundation::Rect const& selection) const;
    void Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& placement) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> PickSingleDeviceAsync(Windows::Foundation::Rect const& selection) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceInformation> PickSingleDeviceAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& placement) const;
    void Hide() const;
    void SetDisplayStatus(Windows::Devices::Enumeration::DeviceInformation const& device, param::hstring const& status, Windows::Devices::Enumeration::DevicePickerDisplayStatusOptions const& options) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePicker> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePicker<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePickerAppearance
{
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::UI::Color ForegroundColor() const;
    void ForegroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Color BackgroundColor() const;
    void BackgroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Color AccentColor() const;
    void AccentColor(Windows::UI::Color const& value) const;
    Windows::UI::Color SelectedForegroundColor() const;
    void SelectedForegroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Color SelectedBackgroundColor() const;
    void SelectedBackgroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Color SelectedAccentColor() const;
    void SelectedAccentColor(Windows::UI::Color const& value) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePickerAppearance> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePickerAppearance<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDevicePickerFilter
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Enumeration::DeviceClass> SupportedDeviceClasses() const;
    Windows::Foundation::Collections::IVector<hstring> SupportedDeviceSelectors() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDevicePickerFilter> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDevicePickerFilter<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceSelectedEventArgs
{
    Windows::Devices::Enumeration::DeviceInformation SelectedDevice() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceSelectedEventArgs> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceSelectedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceUnpairingResult
{
    Windows::Devices::Enumeration::DeviceUnpairingResultStatus Status() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceUnpairingResult> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceUnpairingResult<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceWatcher
{
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceWatcher, &impl::abi_t<Windows::Devices::Enumeration::IDeviceWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformation> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token Updated(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const;
    using Updated_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceWatcher, &impl::abi_t<Windows::Devices::Enumeration::IDeviceWatcher>::remove_Updated>;
    Updated_revoker Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const;
    void Updated(winrt::event_token const& token) const noexcept;
    winrt::event_token Removed(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const;
    using Removed_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceWatcher, &impl::abi_t<Windows::Devices::Enumeration::IDeviceWatcher>::remove_Removed>;
    Removed_revoker Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Devices::Enumeration::DeviceInformationUpdate> const& handler) const;
    void Removed(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceWatcher, &impl::abi_t<Windows::Devices::Enumeration::IDeviceWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token Stopped(Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using Stopped_revoker = impl::event_revoker<Windows::Devices::Enumeration::IDeviceWatcher, &impl::abi_t<Windows::Devices::Enumeration::IDeviceWatcher>::remove_Stopped>;
    Stopped_revoker Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Enumeration::DeviceWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void Stopped(winrt::event_token const& token) const noexcept;
    Windows::Devices::Enumeration::DeviceWatcherStatus Status() const;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceWatcher> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceWatcher<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceWatcher2
{
    Windows::ApplicationModel::Background::DeviceWatcherTrigger GetBackgroundTrigger(param::iterable<Windows::Devices::Enumeration::DeviceWatcherEventKind> const& requestedEventKinds) const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceWatcher2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceWatcher2<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceWatcherEvent
{
    Windows::Devices::Enumeration::DeviceWatcherEventKind Kind() const;
    Windows::Devices::Enumeration::DeviceInformation DeviceInformation() const;
    Windows::Devices::Enumeration::DeviceInformationUpdate DeviceInformationUpdate() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceWatcherEvent> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceWatcherEvent<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IDeviceWatcherTriggerDetails
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Enumeration::DeviceWatcherEvent> DeviceWatcherEvents() const;
};
template <> struct consume<Windows::Devices::Enumeration::IDeviceWatcherTriggerDetails> { template <typename D> using type = consume_Windows_Devices_Enumeration_IDeviceWatcherTriggerDetails<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IEnclosureLocation
{
    bool InDock() const;
    bool InLid() const;
    Windows::Devices::Enumeration::Panel Panel() const;
};
template <> struct consume<Windows::Devices::Enumeration::IEnclosureLocation> { template <typename D> using type = consume_Windows_Devices_Enumeration_IEnclosureLocation<D>; };

template <typename D>
struct consume_Windows_Devices_Enumeration_IEnclosureLocation2
{
    uint32_t RotationAngleInDegreesClockwise() const;
};
template <> struct consume<Windows::Devices::Enumeration::IEnclosureLocation2> { template <typename D> using type = consume_Windows_Devices_Enumeration_IEnclosureLocation2<D>; };

}
