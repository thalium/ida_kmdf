// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Display {

enum class DisplayMonitorUsageKind;
struct DisplayMonitor;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics {

struct Rational;

}

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct DisplayAdapterId;
struct SizeInt32;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX {

enum class DirectXColorSpace;
enum class DirectXPixelFormat;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct Direct3DMultisampleDescription;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core {

enum class DisplayBitsPerChannel : uint32_t
{
    None = 0x0,
    Bpc6 = 0x1,
    Bpc8 = 0x2,
    Bpc10 = 0x4,
    Bpc12 = 0x8,
    Bpc14 = 0x10,
    Bpc16 = 0x20,
};

enum class DisplayDeviceCapability : int32_t
{
    FlipOverride = 0,
};

enum class DisplayManagerOptions : uint32_t
{
    None = 0x0,
    EnforceSourceOwnership = 0x1,
};

enum class DisplayManagerResult : int32_t
{
    Success = 0,
    UnknownFailure = 1,
    TargetAccessDenied = 2,
    TargetStale = 3,
    RemoteSessionNotSupported = 4,
};

enum class DisplayModeQueryOptions : uint32_t
{
    None = 0x0,
    OnlyPreferredResolution = 0x1,
};

enum class DisplayPathScaling : int32_t
{
    Identity = 0,
    Centered = 1,
    Stretched = 2,
    AspectRatioStretched = 3,
    Custom = 4,
    DriverPreferred = 5,
};

enum class DisplayPathStatus : int32_t
{
    Unknown = 0,
    Succeeded = 1,
    Pending = 2,
    Failed = 3,
    FailedAsync = 4,
    InvalidatedAsync = 5,
};

enum class DisplayRotation : int32_t
{
    None = 0,
    Clockwise90Degrees = 1,
    Clockwise180Degrees = 2,
    Clockwise270Degrees = 3,
};

enum class DisplayStateApplyOptions : uint32_t
{
    None = 0x0,
    FailIfStateChanged = 0x1,
    ForceReapply = 0x2,
    ForceModeEnumeration = 0x4,
};

enum class DisplayStateFunctionalizeOptions : uint32_t
{
    None = 0x0,
    FailIfStateChanged = 0x1,
    ValidateTopologyOnly = 0x2,
};

enum class DisplayStateOperationStatus : int32_t
{
    Success = 0,
    PartialFailure = 1,
    UnknownFailure = 2,
    TargetOwnershipLost = 3,
    SystemStateChanged = 4,
    TooManyPathsForAdapter = 5,
    ModesNotSupported = 6,
    RemoteSessionNotSupported = 7,
};

enum class DisplayTargetPersistence : int32_t
{
    None = 0,
    BootPersisted = 1,
    TemporaryPersisted = 2,
    PathPersisted = 3,
};

enum class DisplayTaskSignalKind : int32_t
{
    OnPresentFlipAway = 0,
};

enum class DisplayWireFormatColorSpace : int32_t
{
    BT709 = 0,
    BT2020 = 1,
    ProfileDefinedWideColorGamut = 2,
};

enum class DisplayWireFormatEotf : int32_t
{
    Sdr = 0,
    HdrSmpte2084 = 1,
};

enum class DisplayWireFormatHdrMetadata : int32_t
{
    None = 0,
    Hdr10 = 1,
    Hdr10Plus = 2,
    DolbyVisionLowLatency = 3,
};

enum class DisplayWireFormatPixelEncoding : int32_t
{
    Rgb444 = 0,
    Ycc444 = 1,
    Ycc422 = 2,
    Ycc420 = 3,
    Intensity = 4,
};

struct IDisplayAdapter;
struct IDisplayAdapterStatics;
struct IDisplayDevice;
struct IDisplayFence;
struct IDisplayManager;
struct IDisplayManagerChangedEventArgs;
struct IDisplayManagerDisabledEventArgs;
struct IDisplayManagerEnabledEventArgs;
struct IDisplayManagerPathsFailedOrInvalidatedEventArgs;
struct IDisplayManagerResultWithState;
struct IDisplayManagerStatics;
struct IDisplayModeInfo;
struct IDisplayPath;
struct IDisplayPrimaryDescription;
struct IDisplayPrimaryDescriptionFactory;
struct IDisplayPrimaryDescriptionStatics;
struct IDisplayScanout;
struct IDisplaySource;
struct IDisplayState;
struct IDisplayStateOperationResult;
struct IDisplaySurface;
struct IDisplayTarget;
struct IDisplayTask;
struct IDisplayTaskPool;
struct IDisplayView;
struct IDisplayWireFormat;
struct IDisplayWireFormatFactory;
struct IDisplayWireFormatStatics;
struct DisplayAdapter;
struct DisplayDevice;
struct DisplayFence;
struct DisplayManager;
struct DisplayManagerChangedEventArgs;
struct DisplayManagerDisabledEventArgs;
struct DisplayManagerEnabledEventArgs;
struct DisplayManagerPathsFailedOrInvalidatedEventArgs;
struct DisplayManagerResultWithState;
struct DisplayModeInfo;
struct DisplayPath;
struct DisplayPrimaryDescription;
struct DisplayScanout;
struct DisplaySource;
struct DisplayState;
struct DisplayStateOperationResult;
struct DisplaySurface;
struct DisplayTarget;
struct DisplayTask;
struct DisplayTaskPool;
struct DisplayView;
struct DisplayWireFormat;
struct DisplayPresentationRate;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Devices::Display::Core::DisplayBitsPerChannel> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::Display::Core::DisplayManagerOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::Display::Core::DisplayModeQueryOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::Display::Core::DisplayStateApplyOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions> : std::true_type {};
template <> struct category<Windows::Devices::Display::Core::IDisplayAdapter>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayAdapterStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayDevice>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayFence>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManager>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerResultWithState>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayModeInfo>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayPath>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayPrimaryDescription>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayScanout>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplaySource>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayState>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayStateOperationResult>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplaySurface>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayTarget>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayTask>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayTaskPool>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayView>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayWireFormat>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayWireFormatFactory>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::IDisplayWireFormatStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayAdapter>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayDevice>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayFence>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManager>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerResultWithState>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayModeInfo>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayPath>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayPrimaryDescription>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayScanout>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplaySource>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayState>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayStateOperationResult>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplaySurface>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayTarget>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayTask>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayTaskPool>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayView>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayWireFormat>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayBitsPerChannel>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayDeviceCapability>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerOptions>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayManagerResult>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayModeQueryOptions>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayPathScaling>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayPathStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayRotation>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayStateApplyOptions>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayStateOperationStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayTargetPersistence>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayTaskSignalKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayWireFormatColorSpace>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayWireFormatEotf>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::Core::DisplayPresentationRate>{ using type = struct_category<Windows::Foundation::Numerics::Rational,int32_t>; };
template <> struct name<Windows::Devices::Display::Core::IDisplayAdapter>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayAdapter" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayAdapterStatics>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayAdapterStatics" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayDevice>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayDevice" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayFence>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayFence" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManager>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManager" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerChangedEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerDisabledEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerEnabledEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerPathsFailedOrInvalidatedEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerResultWithState>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerResultWithState" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayManagerStatics>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayManagerStatics" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayModeInfo>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayModeInfo" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayPath>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayPath" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayPrimaryDescription>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayPrimaryDescription" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayPrimaryDescriptionFactory" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayPrimaryDescriptionStatics" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayScanout>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayScanout" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplaySource>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplaySource" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayState>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayState" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayStateOperationResult>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayStateOperationResult" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplaySurface>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplaySurface" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayTarget>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayTarget" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayTask>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayTask" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayTaskPool>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayTaskPool" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayView>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayView" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayWireFormat>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayWireFormat" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayWireFormatFactory>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayWireFormatFactory" }; };
template <> struct name<Windows::Devices::Display::Core::IDisplayWireFormatStatics>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.IDisplayWireFormatStatics" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayAdapter>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayAdapter" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayDevice>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayDevice" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayFence>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayFence" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManager>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManager" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerChangedEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerDisabledEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerEnabledEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerPathsFailedOrInvalidatedEventArgs" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerResultWithState>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerResultWithState" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayModeInfo>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayModeInfo" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayPath>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayPath" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayPrimaryDescription>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayPrimaryDescription" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayScanout>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayScanout" }; };
template <> struct name<Windows::Devices::Display::Core::DisplaySource>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplaySource" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayState>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayState" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayStateOperationResult>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayStateOperationResult" }; };
template <> struct name<Windows::Devices::Display::Core::DisplaySurface>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplaySurface" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayTarget>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayTarget" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayTask>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayTask" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayTaskPool>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayTaskPool" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayView>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayView" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayWireFormat>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayWireFormat" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayBitsPerChannel>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayBitsPerChannel" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayDeviceCapability>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayDeviceCapability" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerOptions>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerOptions" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayManagerResult>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayManagerResult" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayModeQueryOptions>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayModeQueryOptions" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayPathScaling>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayPathScaling" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayPathStatus>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayPathStatus" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayRotation>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayRotation" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayStateApplyOptions>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayStateApplyOptions" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayStateFunctionalizeOptions" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayStateOperationStatus>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayStateOperationStatus" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayTargetPersistence>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayTargetPersistence" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayTaskSignalKind>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayTaskSignalKind" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayWireFormatColorSpace>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayWireFormatColorSpace" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayWireFormatEotf>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayWireFormatEotf" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayWireFormatHdrMetadata" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayWireFormatPixelEncoding" }; };
template <> struct name<Windows::Devices::Display::Core::DisplayPresentationRate>{ static constexpr auto & value{ L"Windows.Devices.Display.Core.DisplayPresentationRate" }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayAdapter>{ static constexpr guid value{ 0xA56F5287,0xF000,0x5F2E,{ 0xB5,0xAC,0x37,0x83,0xA2,0xB6,0x9A,0xF5 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayAdapterStatics>{ static constexpr guid value{ 0x1DAC3CDA,0x481F,0x5469,{ 0x84,0x70,0x82,0xC4,0xBA,0x68,0x0A,0x28 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayDevice>{ static constexpr guid value{ 0xA4C9B62C,0x335F,0x5731,{ 0x8C,0xB4,0xC1,0xCC,0xD4,0x73,0x10,0x70 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayFence>{ static constexpr guid value{ 0x04DCF9EF,0x3406,0x5700,{ 0x8F,0xEC,0x77,0xEB,0xA4,0xC5,0xA7,0x4B } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManager>{ static constexpr guid value{ 0x4ED9245B,0x15EC,0x56E2,{ 0x90,0x72,0x7F,0xE5,0x08,0x4A,0x31,0xA7 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>{ static constexpr guid value{ 0x6ABFA285,0x6CCA,0x5731,{ 0xBC,0xDC,0x42,0xE5,0xD2,0xF5,0xC5,0x0F } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>{ static constexpr guid value{ 0x8726DDE4,0x6793,0x5973,{ 0xA1,0x1F,0x5F,0xFB,0xC9,0x3F,0xDB,0x90 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>{ static constexpr guid value{ 0xF0CF3F6F,0x42FA,0x59A2,{ 0xB2,0x97,0x26,0xE1,0x71,0x3D,0xE8,0x48 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>{ static constexpr guid value{ 0x03A65659,0x1DEC,0x5C15,{ 0xB2,0xA2,0x8F,0xE9,0x12,0x98,0x69,0xFE } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerResultWithState>{ static constexpr guid value{ 0x8E656AA6,0x6614,0x54BE,{ 0xBF,0xEF,0x49,0x94,0x54,0x7F,0x7B,0xE1 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayManagerStatics>{ static constexpr guid value{ 0x2B6B9446,0xB999,0x5535,{ 0x9D,0x69,0x53,0xF0,0x92,0xC7,0x80,0xA1 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayModeInfo>{ static constexpr guid value{ 0x48D513A0,0xF79B,0x5A74,{ 0xA0,0x5E,0xDA,0x82,0x1F,0x47,0x08,0x68 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayPath>{ static constexpr guid value{ 0xB3DFD64A,0x7460,0x5CDE,{ 0x81,0x1B,0xD5,0xAE,0x9F,0x3D,0x9F,0x84 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayPrimaryDescription>{ static constexpr guid value{ 0x872591D2,0xD533,0x50FF,{ 0xA8,0x5E,0x06,0x69,0x61,0x94,0xB7,0x7C } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>{ static constexpr guid value{ 0x1A6AFF7B,0x3637,0x5C46,{ 0xB4,0x79,0x76,0xD5,0x76,0x21,0x6E,0x65 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>{ static constexpr guid value{ 0xE60E4CFB,0x36C9,0x56DD,{ 0x8F,0xA1,0x6F,0xF8,0xC4,0xE0,0xFF,0x07 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayScanout>{ static constexpr guid value{ 0xE3051828,0x1BA5,0x50E7,{ 0x8A,0x39,0xBB,0x1F,0xD2,0xF4,0xF8,0xB9 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplaySource>{ static constexpr guid value{ 0xECD15FC1,0xEADC,0x51BC,{ 0x97,0x1D,0x3B,0xC6,0x28,0xDB,0x2D,0xD4 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayState>{ static constexpr guid value{ 0x08129321,0x11B5,0x5CB2,{ 0x99,0xF8,0xE9,0x0B,0x47,0x9A,0x8A,0x1D } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayStateOperationResult>{ static constexpr guid value{ 0xFCADBFDF,0xDC27,0x5638,{ 0xB7,0xF2,0xEB,0xDF,0xA4,0xF7,0xEA,0x93 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplaySurface>{ static constexpr guid value{ 0x594F6CC6,0x139A,0x56D6,{ 0xA4,0xB1,0x15,0xFE,0x2C,0xB7,0x6A,0xDB } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayTarget>{ static constexpr guid value{ 0xAEC57C6F,0x47B4,0x546B,{ 0x98,0x7C,0xE7,0x3F,0xA7,0x91,0xFE,0x3A } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayTask>{ static constexpr guid value{ 0x5E087448,0x135B,0x5BB0,{ 0xBF,0x63,0x63,0x7F,0x84,0x22,0x7C,0x7A } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayTaskPool>{ static constexpr guid value{ 0xC676253D,0x237D,0x5548,{ 0xAA,0xFA,0x3E,0x51,0x7F,0xEF,0xEF,0x1C } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayView>{ static constexpr guid value{ 0xB0C98CA1,0xB759,0x5B59,{ 0xB1,0xAD,0xF0,0x78,0x6A,0xA9,0xE5,0x3D } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayWireFormat>{ static constexpr guid value{ 0x1ACC967D,0x872C,0x5A38,{ 0xBB,0xB9,0x1D,0x48,0x72,0xB7,0x62,0x55 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayWireFormatFactory>{ static constexpr guid value{ 0xB2EFC8D5,0x09D6,0x55E6,{ 0xAD,0x22,0x90,0x14,0xB3,0xD2,0x52,0x29 } }; };
template <> struct guid_storage<Windows::Devices::Display::Core::IDisplayWireFormatStatics>{ static constexpr guid value{ 0xC575A22D,0xC3E6,0x5F7A,{ 0xBD,0xFB,0x87,0xC6,0xAB,0x86,0x61,0xD5 } }; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayAdapter>{ using type = Windows::Devices::Display::Core::IDisplayAdapter; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayDevice>{ using type = Windows::Devices::Display::Core::IDisplayDevice; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayFence>{ using type = Windows::Devices::Display::Core::IDisplayFence; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManager>{ using type = Windows::Devices::Display::Core::IDisplayManager; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManagerChangedEventArgs>{ using type = Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs>{ using type = Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs>{ using type = Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs>{ using type = Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayManagerResultWithState>{ using type = Windows::Devices::Display::Core::IDisplayManagerResultWithState; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayModeInfo>{ using type = Windows::Devices::Display::Core::IDisplayModeInfo; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayPath>{ using type = Windows::Devices::Display::Core::IDisplayPath; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayPrimaryDescription>{ using type = Windows::Devices::Display::Core::IDisplayPrimaryDescription; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayScanout>{ using type = Windows::Devices::Display::Core::IDisplayScanout; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplaySource>{ using type = Windows::Devices::Display::Core::IDisplaySource; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayState>{ using type = Windows::Devices::Display::Core::IDisplayState; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayStateOperationResult>{ using type = Windows::Devices::Display::Core::IDisplayStateOperationResult; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplaySurface>{ using type = Windows::Devices::Display::Core::IDisplaySurface; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayTarget>{ using type = Windows::Devices::Display::Core::IDisplayTarget; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayTask>{ using type = Windows::Devices::Display::Core::IDisplayTask; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayTaskPool>{ using type = Windows::Devices::Display::Core::IDisplayTaskPool; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayView>{ using type = Windows::Devices::Display::Core::IDisplayView; };
template <> struct default_interface<Windows::Devices::Display::Core::DisplayWireFormat>{ using type = Windows::Devices::Display::Core::IDisplayWireFormat; };

template <> struct abi<Windows::Devices::Display::Core::IDisplayAdapter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInterfacePath(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PciVendorId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PciDeviceId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PciSubSystemId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PciRevision(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayAdapterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromId(struct struct_Windows_Graphics_DisplayAdapterId id, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateScanoutSource(void* target, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePrimary(void* target, void* desc, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateTaskPool(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePeriodicFence(void* target, Windows::Foundation::TimeSpan offsetFromVBlank, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL WaitForVBlank(void* source) noexcept = 0;
    virtual int32_t WINRT_CALL CreateSimpleScanout(void* pSource, void* pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsCapabilitySupported(Windows::Devices::Display::Core::DisplayDeviceCapability capability, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayFence>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCurrentTargets(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentAdapters(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryAcquireTarget(void* target, Windows::Devices::Display::Core::DisplayManagerResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL ReleaseTarget(void* target) noexcept = 0;
    virtual int32_t WINRT_CALL TryReadCurrentStateForAllTargets(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryAcquireTargetsAndReadCurrentState(void* targets, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryAcquireTargetsAndCreateEmptyState(void* targets, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryAcquireTargetsAndCreateSubstate(void* existingState, void* targets, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDisplayDevice(void* adapter, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_Enabled(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Enabled(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Disabled(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Disabled(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PathsFailedOrInvalidated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PathsFailedOrInvalidated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerResultWithState>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ErrorCode(Windows::Devices::Display::Core::DisplayManagerResult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Devices::Display::Core::DisplayManagerOptions options, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayModeInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SourceResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationRate(struct struct_Windows_Devices_Display_Core_DisplayPresentationRate* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInterlaced(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetWireFormatSupportedBitsPerChannel(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding encoding, Windows::Devices::Display::Core::DisplayBitsPerChannel* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsWireFormatSupported(void* wireFormat, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayPath>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_View(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Target(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Display::Core::DisplayPathStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceResolution(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SourceResolution(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsStereo(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetResolution(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetResolution(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationRate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PresentationRate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInterlaced(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsInterlaced(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WireFormat(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WireFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rotation(Windows::Devices::Display::Core::DisplayRotation* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rotation(Windows::Devices::Display::Core::DisplayRotation value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Scaling(Windows::Devices::Display::Core::DisplayPathScaling* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Scaling(Windows::Devices::Display::Core::DisplayPathScaling value) noexcept = 0;
    virtual int32_t WINRT_CALL FindModes(Windows::Devices::Display::Core::DisplayModeQueryOptions flags, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ApplyPropertiesFromMode(void* modeResult) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayPrimaryDescription>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Format(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorSpace(Windows::Graphics::DirectX::DirectXColorSpace* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MultisampleDescription(struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithProperties(void* extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayScanout>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplaySource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourceId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMetadata(winrt::guid Key, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayState>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStale(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Targets(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Views(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ConnectTarget(void* target, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ConnectTargetToView(void* target, void* view, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CanConnectTargetToView(void* target, void* view, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetViewForTarget(void* target, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetPathForTarget(void* target, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL DisconnectTarget(void* target) noexcept = 0;
    virtual int32_t WINRT_CALL TryFunctionalize(Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions options, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryApply(Windows::Devices::Display::Core::DisplayStateApplyOptions options, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL Clone(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayStateOperationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Devices::Display::Core::DisplayStateOperationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplaySurface>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayTarget>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Adapter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeviceInterfacePath(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdapterRelativeId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConnected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVirtualModeEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVirtualTopologyEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsageKind(Windows::Devices::Display::DisplayMonitorUsageKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MonitorPersistence(Windows::Devices::Display::Core::DisplayTargetPersistence* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StableMonitorId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetMonitor(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStale(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsSame(void* otherTarget, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsEqual(void* otherTarget, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayTask>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetScanout(void* scanout) noexcept = 0;
    virtual int32_t WINRT_CALL SetWait(void* readyFence, uint64_t readyFenceValue) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayTaskPool>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateTask(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL ExecuteTask(void* task) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Paths(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentResolution(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentResolution(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPrimaryPath(void* path) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayWireFormat>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PixelEncoding(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitsPerChannel(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorSpace(Windows::Devices::Display::Core::DisplayWireFormatColorSpace* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Eotf(Windows::Devices::Display::Core::DisplayWireFormatEotf* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HdrMetadata(Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayWireFormatFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata hdrMetadata, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::Core::IDisplayWireFormatStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithProperties(void* extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata hdrMetadata, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayAdapter
{
    Windows::Graphics::DisplayAdapterId Id() const;
    hstring DeviceInterfacePath() const;
    uint32_t SourceCount() const;
    uint32_t PciVendorId() const;
    uint32_t PciDeviceId() const;
    uint32_t PciSubSystemId() const;
    uint32_t PciRevision() const;
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayAdapter> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayAdapter<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayAdapterStatics
{
    Windows::Devices::Display::Core::DisplayAdapter FromId(Windows::Graphics::DisplayAdapterId const& id) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayAdapterStatics> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayAdapterStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayDevice
{
    Windows::Devices::Display::Core::DisplaySource CreateScanoutSource(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    Windows::Devices::Display::Core::DisplaySurface CreatePrimary(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayPrimaryDescription const& desc) const;
    Windows::Devices::Display::Core::DisplayTaskPool CreateTaskPool() const;
    Windows::Devices::Display::Core::DisplayFence CreatePeriodicFence(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Foundation::TimeSpan const& offsetFromVBlank) const;
    void WaitForVBlank(Windows::Devices::Display::Core::DisplaySource const& source) const;
    Windows::Devices::Display::Core::DisplayScanout CreateSimpleScanout(Windows::Devices::Display::Core::DisplaySource const& pSource, Windows::Devices::Display::Core::DisplaySurface const& pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval) const;
    bool IsCapabilitySupported(Windows::Devices::Display::Core::DisplayDeviceCapability const& capability) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayDevice> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayDevice<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayFence
{
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayFence> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayFence<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManager
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> GetCurrentTargets() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayAdapter> GetCurrentAdapters() const;
    Windows::Devices::Display::Core::DisplayManagerResult TryAcquireTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    void ReleaseTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    Windows::Devices::Display::Core::DisplayManagerResultWithState TryReadCurrentStateForAllTargets() const;
    Windows::Devices::Display::Core::DisplayManagerResultWithState TryAcquireTargetsAndReadCurrentState(param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const;
    Windows::Devices::Display::Core::DisplayManagerResultWithState TryAcquireTargetsAndCreateEmptyState(param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const;
    Windows::Devices::Display::Core::DisplayManagerResultWithState TryAcquireTargetsAndCreateSubstate(Windows::Devices::Display::Core::DisplayState const& existingState, param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const;
    Windows::Devices::Display::Core::DisplayDevice CreateDisplayDevice(Windows::Devices::Display::Core::DisplayAdapter const& adapter) const;
    winrt::event_token Enabled(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const;
    using Enabled_revoker = impl::event_revoker<Windows::Devices::Display::Core::IDisplayManager, &impl::abi_t<Windows::Devices::Display::Core::IDisplayManager>::remove_Enabled>;
    Enabled_revoker Enabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const;
    void Enabled(winrt::event_token const& token) const noexcept;
    winrt::event_token Disabled(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const;
    using Disabled_revoker = impl::event_revoker<Windows::Devices::Display::Core::IDisplayManager, &impl::abi_t<Windows::Devices::Display::Core::IDisplayManager>::remove_Disabled>;
    Disabled_revoker Disabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const;
    void Disabled(winrt::event_token const& token) const noexcept;
    winrt::event_token Changed(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const;
    using Changed_revoker = impl::event_revoker<Windows::Devices::Display::Core::IDisplayManager, &impl::abi_t<Windows::Devices::Display::Core::IDisplayManager>::remove_Changed>;
    Changed_revoker Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const;
    void Changed(winrt::event_token const& token) const noexcept;
    winrt::event_token PathsFailedOrInvalidated(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const;
    using PathsFailedOrInvalidated_revoker = impl::event_revoker<Windows::Devices::Display::Core::IDisplayManager, &impl::abi_t<Windows::Devices::Display::Core::IDisplayManager>::remove_PathsFailedOrInvalidated>;
    PathsFailedOrInvalidated_revoker PathsFailedOrInvalidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const;
    void PathsFailedOrInvalidated(winrt::event_token const& token) const noexcept;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManager> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManager<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState
{
    Windows::Devices::Display::Core::DisplayManagerResult ErrorCode() const;
    winrt::hresult ExtendedErrorCode() const;
    Windows::Devices::Display::Core::DisplayState State() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerResultWithState> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayManagerStatics
{
    Windows::Devices::Display::Core::DisplayManager Create(Windows::Devices::Display::Core::DisplayManagerOptions const& options) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayManagerStatics> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayManagerStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayModeInfo
{
    Windows::Graphics::SizeInt32 SourceResolution() const;
    bool IsStereo() const;
    Windows::Graphics::DirectX::DirectXPixelFormat SourcePixelFormat() const;
    Windows::Graphics::SizeInt32 TargetResolution() const;
    Windows::Devices::Display::Core::DisplayPresentationRate PresentationRate() const;
    bool IsInterlaced() const;
    Windows::Devices::Display::Core::DisplayBitsPerChannel GetWireFormatSupportedBitsPerChannel(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& encoding) const;
    bool IsWireFormatSupported(Windows::Devices::Display::Core::DisplayWireFormat const& wireFormat) const;
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayModeInfo> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayPath
{
    Windows::Devices::Display::Core::DisplayView View() const;
    Windows::Devices::Display::Core::DisplayTarget Target() const;
    Windows::Devices::Display::Core::DisplayPathStatus Status() const;
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> SourceResolution() const;
    void SourceResolution(optional<Windows::Graphics::SizeInt32> const& value) const;
    Windows::Graphics::DirectX::DirectXPixelFormat SourcePixelFormat() const;
    void SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const;
    bool IsStereo() const;
    void IsStereo(bool value) const;
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> TargetResolution() const;
    void TargetResolution(optional<Windows::Graphics::SizeInt32> const& value) const;
    Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate> PresentationRate() const;
    void PresentationRate(optional<Windows::Devices::Display::Core::DisplayPresentationRate> const& value) const;
    Windows::Foundation::IReference<bool> IsInterlaced() const;
    void IsInterlaced(optional<bool> const& value) const;
    Windows::Devices::Display::Core::DisplayWireFormat WireFormat() const;
    void WireFormat(Windows::Devices::Display::Core::DisplayWireFormat const& value) const;
    Windows::Devices::Display::Core::DisplayRotation Rotation() const;
    void Rotation(Windows::Devices::Display::Core::DisplayRotation const& value) const;
    Windows::Devices::Display::Core::DisplayPathScaling Scaling() const;
    void Scaling(Windows::Devices::Display::Core::DisplayPathScaling const& value) const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayModeInfo> FindModes(Windows::Devices::Display::Core::DisplayModeQueryOptions const& flags) const;
    void ApplyPropertiesFromMode(Windows::Devices::Display::Core::DisplayModeInfo const& modeResult) const;
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayPath> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayPath<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription
{
    uint32_t Width() const;
    uint32_t Height() const;
    Windows::Graphics::DirectX::DirectXPixelFormat Format() const;
    Windows::Graphics::DirectX::DirectXColorSpace ColorSpace() const;
    bool IsStereo() const;
    Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription MultisampleDescription() const;
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayPrimaryDescription> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionFactory
{
    Windows::Devices::Display::Core::DisplayPrimaryDescription CreateInstance(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionStatics
{
    Windows::Devices::Display::Core::DisplayPrimaryDescription CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayScanout
{
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayScanout> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayScanout<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplaySource
{
    Windows::Graphics::DisplayAdapterId AdapterId() const;
    uint32_t SourceId() const;
    Windows::Storage::Streams::IBuffer GetMetadata(winrt::guid const& Key) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplaySource> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplaySource<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayState
{
    bool IsReadOnly() const;
    bool IsStale() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> Targets() const;
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayView> Views() const;
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
    Windows::Devices::Display::Core::DisplayPath ConnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    Windows::Devices::Display::Core::DisplayPath ConnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayView const& view) const;
    bool CanConnectTargetToView(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayView const& view) const;
    Windows::Devices::Display::Core::DisplayView GetViewForTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    Windows::Devices::Display::Core::DisplayPath GetPathForTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    void DisconnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const;
    Windows::Devices::Display::Core::DisplayStateOperationResult TryFunctionalize(Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const& options) const;
    Windows::Devices::Display::Core::DisplayStateOperationResult TryApply(Windows::Devices::Display::Core::DisplayStateApplyOptions const& options) const;
    Windows::Devices::Display::Core::DisplayState Clone() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayState> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayState<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayStateOperationResult
{
    Windows::Devices::Display::Core::DisplayStateOperationStatus Status() const;
    winrt::hresult ExtendedErrorCode() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayStateOperationResult> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayStateOperationResult<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplaySurface
{
};
template <> struct consume<Windows::Devices::Display::Core::IDisplaySurface> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplaySurface<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayTarget
{
    Windows::Devices::Display::Core::DisplayAdapter Adapter() const;
    hstring DeviceInterfacePath() const;
    uint32_t AdapterRelativeId() const;
    bool IsConnected() const;
    bool IsVirtualModeEnabled() const;
    bool IsVirtualTopologyEnabled() const;
    Windows::Devices::Display::DisplayMonitorUsageKind UsageKind() const;
    Windows::Devices::Display::Core::DisplayTargetPersistence MonitorPersistence() const;
    hstring StableMonitorId() const;
    Windows::Devices::Display::DisplayMonitor TryGetMonitor() const;
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
    bool IsStale() const;
    bool IsSame(Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const;
    bool IsEqual(Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayTarget> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayTarget<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayTask
{
    void SetScanout(Windows::Devices::Display::Core::DisplayScanout const& scanout) const;
    void SetWait(Windows::Devices::Display::Core::DisplayFence const& readyFence, uint64_t readyFenceValue) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayTask> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayTask<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayTaskPool
{
    Windows::Devices::Display::Core::DisplayTask CreateTask() const;
    void ExecuteTask(Windows::Devices::Display::Core::DisplayTask const& task) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayTaskPool> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayTaskPool<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayView
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayPath> Paths() const;
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> ContentResolution() const;
    void ContentResolution(optional<Windows::Graphics::SizeInt32> const& value) const;
    void SetPrimaryPath(Windows::Devices::Display::Core::DisplayPath const& path) const;
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayView> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayView<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayWireFormat
{
    Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding PixelEncoding() const;
    int32_t BitsPerChannel() const;
    Windows::Devices::Display::Core::DisplayWireFormatColorSpace ColorSpace() const;
    Windows::Devices::Display::Core::DisplayWireFormatEotf Eotf() const;
    Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata HdrMetadata() const;
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> Properties() const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayWireFormat> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayWireFormatFactory
{
    Windows::Devices::Display::Core::DisplayWireFormat CreateInstance(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayWireFormatFactory> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayWireFormatFactory<D>; };

template <typename D>
struct consume_Windows_Devices_Display_Core_IDisplayWireFormatStatics
{
    Windows::Devices::Display::Core::DisplayWireFormat CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const;
};
template <> struct consume<Windows::Devices::Display::Core::IDisplayWireFormatStatics> { template <typename D> using type = consume_Windows_Devices_Display_Core_IDisplayWireFormatStatics<D>; };

struct struct_Windows_Devices_Display_Core_DisplayPresentationRate
{
    struct{ uint32_t Numerator; uint32_t Denominator; } VerticalSyncRate;
    int32_t VerticalSyncsPerPresentation;
};
template <> struct abi<Windows::Devices::Display::Core::DisplayPresentationRate>{ using type = struct_Windows_Devices_Display_Core_DisplayPresentationRate; };


}
