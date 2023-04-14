// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

struct CoreApplicationView;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct PointInt32;
struct SizeInt32;

}

WINRT_EXPORT namespace winrt::Windows::Media::Core {

struct MediaSource;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::Media::Miracast {

enum class MiracastReceiverApplySettingsStatus : int32_t
{
    Success = 0,
    UnknownFailure = 1,
    MiracastNotSupported = 2,
    AccessDenied = 3,
    FriendlyNameTooLong = 4,
    ModelNameTooLong = 5,
    ModelNumberTooLong = 6,
    InvalidSettings = 7,
};

enum class MiracastReceiverAuthorizationMethod : int32_t
{
    None = 0,
    ConfirmConnection = 1,
    PinDisplayIfRequested = 2,
    PinDisplayRequired = 3,
};

enum class MiracastReceiverDisconnectReason : int32_t
{
    Finished = 0,
    AppSpecificError = 1,
    ConnectionNotAccepted = 2,
    DisconnectedByUser = 3,
    FailedToStartStreaming = 4,
    MediaDecodingError = 5,
    MediaStreamingError = 6,
    MediaDecryptionError = 7,
};

enum class MiracastReceiverGameControllerDeviceUsageMode : int32_t
{
    AsGameController = 0,
    AsMouseAndKeyboard = 1,
};

enum class MiracastReceiverListeningStatus : int32_t
{
    NotListening = 0,
    Listening = 1,
    ConnectionPending = 2,
    Connected = 3,
    DisabledByPolicy = 4,
    TemporarilyDisabled = 5,
};

enum class MiracastReceiverSessionStartStatus : int32_t
{
    Success = 0,
    UnknownFailure = 1,
    MiracastNotSupported = 2,
    AccessDenied = 3,
};

enum class MiracastReceiverWiFiStatus : int32_t
{
    MiracastSupportUndetermined = 0,
    MiracastNotSupported = 1,
    MiracastSupportNotOptimized = 2,
    MiracastSupported = 3,
};

enum class MiracastTransmitterAuthorizationStatus : int32_t
{
    Undecided = 0,
    Allowed = 1,
    AlwaysPrompt = 2,
    Blocked = 3,
};

struct IMiracastReceiver;
struct IMiracastReceiverApplySettingsResult;
struct IMiracastReceiverConnection;
struct IMiracastReceiverConnectionCreatedEventArgs;
struct IMiracastReceiverCursorImageChannel;
struct IMiracastReceiverCursorImageChannelSettings;
struct IMiracastReceiverDisconnectedEventArgs;
struct IMiracastReceiverGameControllerDevice;
struct IMiracastReceiverInputDevices;
struct IMiracastReceiverKeyboardDevice;
struct IMiracastReceiverMediaSourceCreatedEventArgs;
struct IMiracastReceiverSession;
struct IMiracastReceiverSessionStartResult;
struct IMiracastReceiverSettings;
struct IMiracastReceiverStatus;
struct IMiracastReceiverStreamControl;
struct IMiracastReceiverVideoStreamSettings;
struct IMiracastTransmitter;
struct MiracastReceiver;
struct MiracastReceiverApplySettingsResult;
struct MiracastReceiverConnection;
struct MiracastReceiverConnectionCreatedEventArgs;
struct MiracastReceiverCursorImageChannel;
struct MiracastReceiverCursorImageChannelSettings;
struct MiracastReceiverDisconnectedEventArgs;
struct MiracastReceiverGameControllerDevice;
struct MiracastReceiverInputDevices;
struct MiracastReceiverKeyboardDevice;
struct MiracastReceiverMediaSourceCreatedEventArgs;
struct MiracastReceiverSession;
struct MiracastReceiverSessionStartResult;
struct MiracastReceiverSettings;
struct MiracastReceiverStatus;
struct MiracastReceiverStreamControl;
struct MiracastReceiverVideoStreamSettings;
struct MiracastTransmitter;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Miracast::IMiracastReceiver>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverConnection>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverInputDevices>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverSession>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverSessionStartResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverSettings>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverStatus>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverStreamControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::IMiracastTransmitter>{ using type = interface_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiver>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverConnection>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverCursorImageChannel>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverGameControllerDevice>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverInputDevices>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverKeyboardDevice>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverSession>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverSessionStartResult>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverSettings>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverStatus>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverStreamControl>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastTransmitter>{ using type = class_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverApplySettingsStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverAuthorizationMethod>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverDisconnectReason>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverListeningStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverSessionStartStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastReceiverWiFiStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus>{ using type = enum_category; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiver>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiver" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverApplySettingsResult" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverConnection>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverConnection" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverConnectionCreatedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannel" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverCursorImageChannelSettings" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverDisconnectedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverGameControllerDevice" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverInputDevices>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverInputDevices" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverKeyboardDevice" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverMediaSourceCreatedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverSession>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverSession" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverSessionStartResult>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverSessionStartResult" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverSettings" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverStatus" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverStreamControl>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverStreamControl" }; };
template <> struct name<Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastReceiverVideoStreamSettings" }; };
template <> struct name<Windows::Media::Miracast::IMiracastTransmitter>{ static constexpr auto & value{ L"Windows.Media.Miracast.IMiracastTransmitter" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiver>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiver" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverApplySettingsResult" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverConnection>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverConnection" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverConnectionCreatedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverCursorImageChannel>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverCursorImageChannel" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverCursorImageChannelSettings" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverDisconnectedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverGameControllerDevice>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverGameControllerDevice" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverInputDevices>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverInputDevices" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverKeyboardDevice>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverKeyboardDevice" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverMediaSourceCreatedEventArgs" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverSession>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverSession" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverSessionStartResult>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverSessionStartResult" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverSettings" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverStatus" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverStreamControl>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverStreamControl" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverVideoStreamSettings" }; };
template <> struct name<Windows::Media::Miracast::MiracastTransmitter>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastTransmitter" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverApplySettingsStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverApplySettingsStatus" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverAuthorizationMethod>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverAuthorizationMethod" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverDisconnectReason>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverDisconnectReason" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverGameControllerDeviceUsageMode" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverListeningStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverListeningStatus" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverSessionStartStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverSessionStartStatus" }; };
template <> struct name<Windows::Media::Miracast::MiracastReceiverWiFiStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastReceiverWiFiStatus" }; };
template <> struct name<Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus>{ static constexpr auto & value{ L"Windows.Media.Miracast.MiracastTransmitterAuthorizationStatus" }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiver>{ static constexpr guid value{ 0x7A315258,0xE444,0x51B4,{ 0xAF,0xF7,0xB8,0x8D,0xAA,0x12,0x29,0xE0 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>{ static constexpr guid value{ 0xD0AA6272,0x09CD,0x58E1,{ 0xA4,0xF2,0x5D,0x51,0x43,0xD3,0x12,0xF9 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverConnection>{ static constexpr guid value{ 0x704B2F36,0xD2E5,0x551F,{ 0xA8,0x54,0xF8,0x22,0xB7,0x91,0x7D,0x28 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>{ static constexpr guid value{ 0x7D8DFA39,0x307A,0x5C0F,{ 0x94,0xBD,0xD0,0xC6,0x9D,0x16,0x99,0x82 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>{ static constexpr guid value{ 0xD9AC332D,0x723A,0x5A9D,{ 0xB9,0x0A,0x81,0x15,0x3E,0xFA,0x2A,0x0F } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>{ static constexpr guid value{ 0xCCDBEDFF,0xBD00,0x5B9C,{ 0x8E,0x4C,0x00,0xCA,0xCF,0x86,0xB6,0x34 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>{ static constexpr guid value{ 0xD9A15E5E,0x5FEE,0x57E6,{ 0xB4,0xB0,0x04,0x72,0x7D,0xB9,0x32,0x29 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>{ static constexpr guid value{ 0x2D7171E8,0xBED4,0x5118,{ 0xA0,0x58,0xE2,0x47,0x7E,0xB5,0x88,0x8D } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverInputDevices>{ static constexpr guid value{ 0xDA35BB02,0x28AA,0x5EE8,{ 0x96,0xF5,0xA4,0x29,0x01,0xC6,0x6F,0x00 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>{ static constexpr guid value{ 0xBEB67272,0x06C0,0x54FF,{ 0xAC,0x96,0x21,0x74,0x64,0xFF,0x25,0x01 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>{ static constexpr guid value{ 0x17CF519E,0x1246,0x531D,{ 0x94,0x5A,0x6B,0x15,0x8E,0x39,0xC3,0xAA } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverSession>{ static constexpr guid value{ 0x1D2BCDB4,0xEF8B,0x5209,{ 0xBF,0xC9,0xC3,0x21,0x16,0x50,0x48,0x03 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverSessionStartResult>{ static constexpr guid value{ 0xB7C573EE,0x40CA,0x51FF,{ 0x95,0xF2,0xC9,0xDE,0x34,0xF2,0xE9,0x0E } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverSettings>{ static constexpr guid value{ 0x57CD2F24,0xC55A,0x5FBE,{ 0x94,0x64,0xEB,0x05,0x30,0x77,0x05,0xDD } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverStatus>{ static constexpr guid value{ 0xC28A5591,0x23AB,0x519E,{ 0xAD,0x09,0x90,0xBF,0xF6,0xDC,0xC8,0x7E } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverStreamControl>{ static constexpr guid value{ 0x38EA2D8B,0x2769,0x5AD7,{ 0x8A,0x8A,0x25,0x4B,0x9D,0xF7,0xBA,0x82 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>{ static constexpr guid value{ 0x169B5E1B,0x149D,0x52D0,{ 0xB1,0x26,0x6F,0x89,0x74,0x4E,0x4F,0x50 } }; };
template <> struct guid_storage<Windows::Media::Miracast::IMiracastTransmitter>{ static constexpr guid value{ 0x342D79FD,0x2E64,0x5508,{ 0x8A,0x30,0x83,0x3D,0x1E,0xAC,0x70,0xD0 } }; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiver>{ using type = Windows::Media::Miracast::IMiracastReceiver; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverApplySettingsResult>{ using type = Windows::Media::Miracast::IMiracastReceiverApplySettingsResult; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverConnection>{ using type = Windows::Media::Miracast::IMiracastReceiverConnection; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs>{ using type = Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverCursorImageChannel>{ using type = Windows::Media::Miracast::IMiracastReceiverCursorImageChannel; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings>{ using type = Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs>{ using type = Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverGameControllerDevice>{ using type = Windows::Media::Miracast::IMiracastReceiverGameControllerDevice; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverInputDevices>{ using type = Windows::Media::Miracast::IMiracastReceiverInputDevices; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverKeyboardDevice>{ using type = Windows::Media::Miracast::IMiracastReceiverKeyboardDevice; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs>{ using type = Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverSession>{ using type = Windows::Media::Miracast::IMiracastReceiverSession; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverSessionStartResult>{ using type = Windows::Media::Miracast::IMiracastReceiverSessionStartResult; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverSettings>{ using type = Windows::Media::Miracast::IMiracastReceiverSettings; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverStatus>{ using type = Windows::Media::Miracast::IMiracastReceiverStatus; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverStreamControl>{ using type = Windows::Media::Miracast::IMiracastReceiverStreamControl; };
template <> struct default_interface<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings>{ using type = Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings; };
template <> struct default_interface<Windows::Media::Miracast::MiracastTransmitter>{ using type = Windows::Media::Miracast::IMiracastTransmitter; };

template <> struct abi<Windows::Media::Miracast::IMiracastReceiver>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefaultSettings(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentSettings(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentSettingsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DisconnectAllAndApplySettings(void* settings, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisconnectAllAndApplySettingsAsync(void* settings, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStatus(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetStatusAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSession(void* view, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSessionAsync(void* view, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ClearKnownTransmitters() noexcept = 0;
    virtual int32_t WINRT_CALL RemoveKnownTransmitter(void* transmitter) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverApplySettingsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Miracast::MiracastReceiverApplySettingsStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverConnection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason reason) noexcept = 0;
    virtual int32_t WINRT_CALL DisconnectWithMessage(Windows::Media::Miracast::MiracastReceiverDisconnectReason reason, void* message) noexcept = 0;
    virtual int32_t WINRT_CALL Pause() noexcept = 0;
    virtual int32_t WINRT_CALL PauseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL Resume() noexcept = 0;
    virtual int32_t WINRT_CALL ResumeAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_Transmitter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputDevices(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CursorImageChannel(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StreamControl(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pin(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(struct struct_Windows_Graphics_PointInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImageStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ImageStreamChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ImageStreamChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PositionChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PositionChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxImageSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxImageSize(struct struct_Windows_Graphics_SizeInt32 value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TransmitInput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransmitInput(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRequestedByTransmitter(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTransmittingInput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverInputDevices>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Keyboard(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GameController(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TransmitInput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TransmitInput(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRequestedByTransmitter(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTransmittingInput(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CursorImageChannelSettings(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ConnectionCreated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ConnectionCreated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaSourceCreated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaSourceCreated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Disconnected(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Disconnected(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllowConnectionTakeover(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowConnectionTakeover(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSimultaneousConnections(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxSimultaneousConnections(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL Start(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL StartAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverSessionStartResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Miracast::MiracastReceiverSessionStartStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FriendlyName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModelName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ModelName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModelNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ModelNumber(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequireAuthorizationFromKnownTransmitters(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RequireAuthorizationFromKnownTransmitters(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ListeningStatus(Windows::Media::Miracast::MiracastReceiverListeningStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WiFiStatus(Windows::Media::Miracast::MiracastReceiverWiFiStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConnectionTakeoverSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSimultaneousConnections(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KnownTransmitters(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverStreamControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetVideoStreamSettings(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetVideoStreamSettingsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SuggestVideoStreamSettings(void* settings) noexcept = 0;
    virtual int32_t WINRT_CALL SuggestVideoStreamSettingsAsync(void* settings, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_MuteAudio(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MuteAudio(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Size(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Size(struct struct_Windows_Graphics_SizeInt32 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Bitrate(int32_t value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Miracast::IMiracastTransmitter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL GetConnections(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_MacAddress(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastConnectionTime(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiver
{
    Windows::Media::Miracast::MiracastReceiverSettings GetDefaultSettings() const;
    Windows::Media::Miracast::MiracastReceiverSettings GetCurrentSettings() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSettings> GetCurrentSettingsAsync() const;
    Windows::Media::Miracast::MiracastReceiverApplySettingsResult DisconnectAllAndApplySettings(Windows::Media::Miracast::MiracastReceiverSettings const& settings) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverApplySettingsResult> DisconnectAllAndApplySettingsAsync(Windows::Media::Miracast::MiracastReceiverSettings const& settings) const;
    Windows::Media::Miracast::MiracastReceiverStatus GetStatus() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverStatus> GetStatusAsync() const;
    winrt::event_token StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const& handler) const;
    using StatusChanged_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiver, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiver>::remove_StatusChanged>;
    StatusChanged_revoker StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiver, Windows::Foundation::IInspectable> const& handler) const;
    void StatusChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::Miracast::MiracastReceiverSession CreateSession(Windows::ApplicationModel::Core::CoreApplicationView const& view) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSession> CreateSessionAsync(Windows::ApplicationModel::Core::CoreApplicationView const& view) const;
    void ClearKnownTransmitters() const;
    void RemoveKnownTransmitter(Windows::Media::Miracast::MiracastTransmitter const& transmitter) const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiver> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiver<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult
{
    Windows::Media::Miracast::MiracastReceiverApplySettingsStatus Status() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverApplySettingsResult> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverApplySettingsResult<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverConnection
{
    void Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason) const;
    void Disconnect(Windows::Media::Miracast::MiracastReceiverDisconnectReason const& reason, param::hstring const& message) const;
    void Pause() const;
    Windows::Foundation::IAsyncAction PauseAsync() const;
    void Resume() const;
    Windows::Foundation::IAsyncAction ResumeAsync() const;
    Windows::Media::Miracast::MiracastTransmitter Transmitter() const;
    Windows::Media::Miracast::MiracastReceiverInputDevices InputDevices() const;
    Windows::Media::Miracast::MiracastReceiverCursorImageChannel CursorImageChannel() const;
    Windows::Media::Miracast::MiracastReceiverStreamControl StreamControl() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverConnection> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverConnection<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs
{
    Windows::Media::Miracast::MiracastReceiverConnection Connection() const;
    hstring Pin() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverConnectionCreatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel
{
    bool IsEnabled() const;
    Windows::Graphics::SizeInt32 MaxImageSize() const;
    Windows::Graphics::PointInt32 Position() const;
    Windows::Storage::Streams::IRandomAccessStreamWithContentType ImageStream() const;
    winrt::event_token ImageStreamChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const;
    using ImageStreamChanged_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>::remove_ImageStreamChanged>;
    ImageStreamChanged_revoker ImageStreamChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const;
    void ImageStreamChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const;
    using PositionChanged_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel>::remove_PositionChanged>;
    PositionChanged_revoker PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverCursorImageChannel, Windows::Foundation::IInspectable> const& handler) const;
    void PositionChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverCursorImageChannel> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannel<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings
{
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::Graphics::SizeInt32 MaxImageSize() const;
    void MaxImageSize(Windows::Graphics::SizeInt32 const& value) const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverCursorImageChannelSettings<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs
{
    Windows::Media::Miracast::MiracastReceiverConnection Connection() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverDisconnectedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice
{
    bool TransmitInput() const;
    void TransmitInput(bool value) const;
    bool IsRequestedByTransmitter() const;
    bool IsTransmittingInput() const;
    Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode Mode() const;
    void Mode(Windows::Media::Miracast::MiracastReceiverGameControllerDeviceUsageMode const& value) const;
    winrt::event_token Changed(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const& handler) const;
    using Changed_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice>::remove_Changed>;
    Changed_revoker Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverGameControllerDevice, Windows::Foundation::IInspectable> const& handler) const;
    void Changed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverGameControllerDevice> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverGameControllerDevice<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverInputDevices
{
    Windows::Media::Miracast::MiracastReceiverKeyboardDevice Keyboard() const;
    Windows::Media::Miracast::MiracastReceiverGameControllerDevice GameController() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverInputDevices> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverInputDevices<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice
{
    bool TransmitInput() const;
    void TransmitInput(bool value) const;
    bool IsRequestedByTransmitter() const;
    bool IsTransmittingInput() const;
    winrt::event_token Changed(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const& handler) const;
    using Changed_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice>::remove_Changed>;
    Changed_revoker Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverKeyboardDevice, Windows::Foundation::IInspectable> const& handler) const;
    void Changed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverKeyboardDevice> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverKeyboardDevice<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs
{
    Windows::Media::Miracast::MiracastReceiverConnection Connection() const;
    Windows::Media::Core::MediaSource MediaSource() const;
    Windows::Media::Miracast::MiracastReceiverCursorImageChannelSettings CursorImageChannelSettings() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverMediaSourceCreatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverSession
{
    winrt::event_token ConnectionCreated(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const;
    using ConnectionCreated_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverSession, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverSession>::remove_ConnectionCreated>;
    ConnectionCreated_revoker ConnectionCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverConnectionCreatedEventArgs> const& handler) const;
    void ConnectionCreated(winrt::event_token const& token) const noexcept;
    winrt::event_token MediaSourceCreated(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const;
    using MediaSourceCreated_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverSession, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverSession>::remove_MediaSourceCreated>;
    MediaSourceCreated_revoker MediaSourceCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverMediaSourceCreatedEventArgs> const& handler) const;
    void MediaSourceCreated(winrt::event_token const& token) const noexcept;
    winrt::event_token Disconnected(Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const;
    using Disconnected_revoker = impl::event_revoker<Windows::Media::Miracast::IMiracastReceiverSession, &impl::abi_t<Windows::Media::Miracast::IMiracastReceiverSession>::remove_Disconnected>;
    Disconnected_revoker Disconnected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Miracast::MiracastReceiverSession, Windows::Media::Miracast::MiracastReceiverDisconnectedEventArgs> const& handler) const;
    void Disconnected(winrt::event_token const& token) const noexcept;
    bool AllowConnectionTakeover() const;
    void AllowConnectionTakeover(bool value) const;
    int32_t MaxSimultaneousConnections() const;
    void MaxSimultaneousConnections(int32_t value) const;
    Windows::Media::Miracast::MiracastReceiverSessionStartResult Start() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverSessionStartResult> StartAsync() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverSession> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverSession<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult
{
    Windows::Media::Miracast::MiracastReceiverSessionStartStatus Status() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverSessionStartResult> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverSessionStartResult<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverSettings
{
    hstring FriendlyName() const;
    void FriendlyName(param::hstring const& value) const;
    hstring ModelName() const;
    void ModelName(param::hstring const& value) const;
    hstring ModelNumber() const;
    void ModelNumber(param::hstring const& value) const;
    Windows::Media::Miracast::MiracastReceiverAuthorizationMethod AuthorizationMethod() const;
    void AuthorizationMethod(Windows::Media::Miracast::MiracastReceiverAuthorizationMethod const& value) const;
    bool RequireAuthorizationFromKnownTransmitters() const;
    void RequireAuthorizationFromKnownTransmitters(bool value) const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverSettings> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverSettings<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverStatus
{
    Windows::Media::Miracast::MiracastReceiverListeningStatus ListeningStatus() const;
    Windows::Media::Miracast::MiracastReceiverWiFiStatus WiFiStatus() const;
    bool IsConnectionTakeoverSupported() const;
    int32_t MaxSimultaneousConnections() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastTransmitter> KnownTransmitters() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverStatus> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverStatus<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverStreamControl
{
    Windows::Media::Miracast::MiracastReceiverVideoStreamSettings GetVideoStreamSettings() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Miracast::MiracastReceiverVideoStreamSettings> GetVideoStreamSettingsAsync() const;
    void SuggestVideoStreamSettings(Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const;
    Windows::Foundation::IAsyncAction SuggestVideoStreamSettingsAsync(Windows::Media::Miracast::MiracastReceiverVideoStreamSettings const& settings) const;
    bool MuteAudio() const;
    void MuteAudio(bool value) const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverStreamControl> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverStreamControl<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings
{
    Windows::Graphics::SizeInt32 Size() const;
    void Size(Windows::Graphics::SizeInt32 const& value) const;
    int32_t Bitrate() const;
    void Bitrate(int32_t value) const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastReceiverVideoStreamSettings<D>; };

template <typename D>
struct consume_Windows_Media_Miracast_IMiracastTransmitter
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
    Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus AuthorizationStatus() const;
    void AuthorizationStatus(Windows::Media::Miracast::MiracastTransmitterAuthorizationStatus const& value) const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Miracast::MiracastReceiverConnection> GetConnections() const;
    hstring MacAddress() const;
    Windows::Foundation::DateTime LastConnectionTime() const;
};
template <> struct consume<Windows::Media::Miracast::IMiracastTransmitter> { template <typename D> using type = consume_Windows_Media_Miracast_IMiracastTransmitter<D>; };

}
