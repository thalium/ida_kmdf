// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IInputStream;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

struct HttpClient;
struct HttpResponseMessage;

}

WINRT_EXPORT namespace winrt::Windows::Media::Streaming::Adaptive {

enum class AdaptiveMediaSourceCreationStatus : int32_t
{
    Success = 0,
    ManifestDownloadFailure = 1,
    ManifestParseFailure = 2,
    UnsupportedManifestContentType = 3,
    UnsupportedManifestVersion = 4,
    UnsupportedManifestProfile = 5,
    UnknownFailure = 6,
};

enum class AdaptiveMediaSourceDiagnosticType : int32_t
{
    ManifestUnchangedUponReload = 0,
    ManifestMismatchUponReload = 1,
    ManifestSignaledEndOfLiveEventUponReload = 2,
    MediaSegmentSkipped = 3,
    ResourceNotFound = 4,
    ResourceTimedOut = 5,
    ResourceParsingError = 6,
    BitrateDisabled = 7,
    FatalMediaSourceError = 8,
};

enum class AdaptiveMediaSourceDownloadBitrateChangedReason : int32_t
{
    SufficientInboundBitsPerSecond = 0,
    InsufficientInboundBitsPerSecond = 1,
    LowBufferLevel = 2,
    PositionChanged = 3,
    TrackSelectionChanged = 4,
    DesiredBitratesChanged = 5,
    ErrorInPreviousBitrate = 6,
};

enum class AdaptiveMediaSourceResourceType : int32_t
{
    Manifest = 0,
    InitializationSegment = 1,
    MediaSegment = 2,
    Key = 3,
    InitializationVector = 4,
    MediaSegmentIndex = 5,
};

struct IAdaptiveMediaSource;
struct IAdaptiveMediaSource2;
struct IAdaptiveMediaSource3;
struct IAdaptiveMediaSourceAdvancedSettings;
struct IAdaptiveMediaSourceCorrelatedTimes;
struct IAdaptiveMediaSourceCreationResult;
struct IAdaptiveMediaSourceCreationResult2;
struct IAdaptiveMediaSourceDiagnosticAvailableEventArgs;
struct IAdaptiveMediaSourceDiagnosticAvailableEventArgs2;
struct IAdaptiveMediaSourceDiagnosticAvailableEventArgs3;
struct IAdaptiveMediaSourceDiagnostics;
struct IAdaptiveMediaSourceDownloadBitrateChangedEventArgs;
struct IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2;
struct IAdaptiveMediaSourceDownloadCompletedEventArgs;
struct IAdaptiveMediaSourceDownloadCompletedEventArgs2;
struct IAdaptiveMediaSourceDownloadCompletedEventArgs3;
struct IAdaptiveMediaSourceDownloadFailedEventArgs;
struct IAdaptiveMediaSourceDownloadFailedEventArgs2;
struct IAdaptiveMediaSourceDownloadFailedEventArgs3;
struct IAdaptiveMediaSourceDownloadRequestedDeferral;
struct IAdaptiveMediaSourceDownloadRequestedEventArgs;
struct IAdaptiveMediaSourceDownloadRequestedEventArgs2;
struct IAdaptiveMediaSourceDownloadRequestedEventArgs3;
struct IAdaptiveMediaSourceDownloadResult;
struct IAdaptiveMediaSourceDownloadResult2;
struct IAdaptiveMediaSourceDownloadStatistics;
struct IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs;
struct IAdaptiveMediaSourceStatics;
struct AdaptiveMediaSource;
struct AdaptiveMediaSourceAdvancedSettings;
struct AdaptiveMediaSourceCorrelatedTimes;
struct AdaptiveMediaSourceCreationResult;
struct AdaptiveMediaSourceDiagnosticAvailableEventArgs;
struct AdaptiveMediaSourceDiagnostics;
struct AdaptiveMediaSourceDownloadBitrateChangedEventArgs;
struct AdaptiveMediaSourceDownloadCompletedEventArgs;
struct AdaptiveMediaSourceDownloadFailedEventArgs;
struct AdaptiveMediaSourceDownloadRequestedDeferral;
struct AdaptiveMediaSourceDownloadRequestedEventArgs;
struct AdaptiveMediaSourceDownloadResult;
struct AdaptiveMediaSourceDownloadStatistics;
struct AdaptiveMediaSourcePlaybackBitrateChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus>{ using type = enum_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType>{ using type = enum_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason>{ using type = enum_category; };
template <> struct category<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>{ using type = enum_category; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSource" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSource2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSource3" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceAdvancedSettings" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceCorrelatedTimes" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceCreationResult" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceCreationResult2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDiagnosticAvailableEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDiagnosticAvailableEventArgs2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDiagnosticAvailableEventArgs3" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDiagnostics" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadBitrateChangedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadCompletedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadCompletedEventArgs2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadCompletedEventArgs3" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadFailedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadFailedEventArgs2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadFailedEventArgs3" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadRequestedDeferral" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadRequestedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadRequestedEventArgs2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadRequestedEventArgs3" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadResult" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadResult2" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceDownloadStatistics" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.IAdaptiveMediaSourceStatics" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSource" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceAdvancedSettings" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceCorrelatedTimes" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceCreationResult" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDiagnosticAvailableEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDiagnostics" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadBitrateChangedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadCompletedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadFailedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadRequestedDeferral" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadRequestedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadResult" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadStatistics" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourcePlaybackBitrateChangedEventArgs" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceCreationStatus" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDiagnosticType" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceDownloadBitrateChangedReason" }; };
template <> struct name<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>{ static constexpr auto & value{ L"Windows.Media.Streaming.Adaptive.AdaptiveMediaSourceResourceType" }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>{ static constexpr guid value{ 0x4C7332EF,0xD39F,0x4396,{ 0xB4,0xD9,0x04,0x39,0x57,0xA7,0xC9,0x64 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2>{ static constexpr guid value{ 0x17890342,0x6760,0x4BB9,{ 0xA5,0x8A,0xF7,0xAA,0x98,0xB0,0x8C,0x0E } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3>{ static constexpr guid value{ 0xBA7023FD,0xC334,0x461B,{ 0xA3,0x6E,0xC9,0x9F,0x54,0xF7,0x17,0x4A } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings>{ static constexpr guid value{ 0x55DB1680,0x1AEB,0x47DC,{ 0xAA,0x08,0x9A,0x11,0x61,0x0B,0xA4,0x5A } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes>{ static constexpr guid value{ 0x05108787,0xE032,0x48E1,{ 0xAB,0x8D,0x00,0x2B,0x0B,0x30,0x51,0xDF } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult>{ static constexpr guid value{ 0x4686B6B2,0x800F,0x4E31,{ 0x90,0x93,0x76,0xD4,0x78,0x20,0x13,0xE7 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2>{ static constexpr guid value{ 0x1C3243BF,0x1C44,0x404B,{ 0xA2,0x01,0xDF,0x45,0xAC,0x78,0x98,0xE8 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs>{ static constexpr guid value{ 0x3AF64F06,0x6D9C,0x494A,{ 0xB7,0xA9,0xB3,0xA5,0xDE,0xE6,0xAD,0x68 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2>{ static constexpr guid value{ 0x8C6DD857,0x16A5,0x4D9F,{ 0x81,0x0E,0x00,0xBD,0x90,0x1B,0x3E,0xF9 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3>{ static constexpr guid value{ 0xC3650CD5,0xDAEB,0x4103,{ 0x84,0xDA,0x68,0x76,0x9A,0xD5,0x13,0xFF } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>{ static constexpr guid value{ 0x9B24EE68,0x962E,0x448C,{ 0xAE,0xBF,0xB2,0x9B,0x56,0x09,0x8E,0x23 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ static constexpr guid value{ 0x670C0A44,0xE04E,0x4EFF,{ 0x81,0x6A,0x17,0x39,0x9F,0x78,0xF4,0xBA } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2>{ static constexpr guid value{ 0xF3F1F444,0x96AE,0x4DE0,{ 0xB5,0x40,0x2B,0x32,0x46,0xE6,0x96,0x8C } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs>{ static constexpr guid value{ 0x19240DC3,0x5B37,0x4A1A,{ 0x89,0x70,0xD6,0x21,0xCB,0x6C,0xA8,0x3B } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2>{ static constexpr guid value{ 0x704744C4,0x964A,0x40E4,{ 0xAF,0x95,0x91,0x77,0xDD,0x6D,0xFA,0x00 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3>{ static constexpr guid value{ 0x0F8A8BD1,0x93B2,0x47C6,{ 0xBA,0xDC,0x8B,0xE2,0xC8,0xF7,0xF6,0xE8 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs>{ static constexpr guid value{ 0x37739048,0xF4AB,0x40A4,{ 0xB1,0x35,0xC6,0xDF,0xD8,0xBD,0x7F,0xF1 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2>{ static constexpr guid value{ 0x70919568,0x967C,0x4986,{ 0x90,0xC5,0xC6,0xFC,0x4B,0x31,0xE2,0xD8 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3>{ static constexpr guid value{ 0xD0354549,0x1132,0x4A10,{ 0x91,0x5A,0xC2,0x21,0x1B,0x5B,0x94,0x09 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral>{ static constexpr guid value{ 0x05C68F64,0xFA20,0x4DBD,{ 0x98,0x21,0x4B,0xF4,0xC9,0xBF,0x77,0xAB } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs>{ static constexpr guid value{ 0xC83FDFFD,0x44A9,0x47A2,{ 0xBF,0x96,0x03,0x39,0x8B,0x4B,0xFA,0xAF } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2>{ static constexpr guid value{ 0xB37D8BFE,0xAA44,0x4D82,{ 0x82,0x5B,0x61,0x1D,0xE3,0xBC,0xFE,0xCB } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3>{ static constexpr guid value{ 0x333C50FD,0x4F62,0x4481,{ 0xAB,0x44,0x1E,0x47,0xB0,0x57,0x42,0x25 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult>{ static constexpr guid value{ 0xF4AFDC73,0xBCEE,0x4A6A,{ 0x9F,0x0A,0xFE,0xC4,0x1E,0x23,0x39,0xB0 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2>{ static constexpr guid value{ 0x15552CB7,0x7B80,0x4AC4,{ 0x86,0x60,0xA4,0xB9,0x7F,0x7C,0x70,0xF0 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics>{ static constexpr guid value{ 0xA306CEFB,0xE96A,0x4DFF,{ 0xA9,0xB8,0x1A,0xE0,0x8C,0x01,0xAE,0x98 } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ static constexpr guid value{ 0x23A29F6D,0x7DDA,0x4A51,{ 0x87,0xA9,0x6F,0xA8,0xC5,0xB2,0x92,0xBE } }; };
template <> struct guid_storage<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>{ static constexpr guid value{ 0x50A6BD5D,0x66EF,0x4CD3,{ 0x95,0x79,0x9E,0x66,0x05,0x07,0xDC,0x3F } }; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics; };
template <> struct default_interface<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ using type = Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs; };

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsLive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredLiveOffset(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredLiveOffset(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InitialBitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InitialBitrate(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentDownloadBitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentPlaybackBitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AvailableBitrates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredMinBitrate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredMinBitrate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredMaxBitrate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredMaxBitrate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioOnlyPlayback(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InboundBitsPerSecond(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL add_DownloadBitrateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DownloadBitrateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlaybackBitrateChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlaybackBitrateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DownloadRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DownloadRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DownloadCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DownloadCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DownloadFailed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DownloadFailed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdvancedSettings(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MinLiveOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSeekableWindowSize(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredSeekableWindowSize(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredSeekableWindowSize(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Diagnostics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCorrelatedTimes(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllSegmentsIndependent(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllSegmentsIndependent(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredBitrateHeadroomRatio(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredBitrateHeadroomRatio(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitrateDowngradeTriggerRatio(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BitrateDowngradeTriggerRatio(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationTimeStamp(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProgramDateTime(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DiagnosticType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SegmentId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_DiagnosticAvailable(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DiagnosticAvailable(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldValue(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewValue(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Statistics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Statistics(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Result(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** deferral) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ResourceUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InputStream(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Buffer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Buffer(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExtendedStatus(uint32_t value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ResourceByteRangeOffset(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ResourceByteRangeLength(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentBytesReceivedCount(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeToHeadersReceived(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeToFirstByteReceived(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimeToLastByteReceived(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldValue(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewValue(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioOnly(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsContentTypeSupported(void* contentType, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromUriAsync(void* uri, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromUriWithDownloaderAsync(void* uri, void* httpClient, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromStreamAsync(void* stream, void* uri, void* contentType, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromStreamWithDownloaderAsync(void* stream, void* uri, void* contentType, void* httpClient, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource
{
    bool IsLive() const;
    Windows::Foundation::TimeSpan DesiredLiveOffset() const;
    void DesiredLiveOffset(Windows::Foundation::TimeSpan const& value) const;
    uint32_t InitialBitrate() const;
    void InitialBitrate(uint32_t value) const;
    uint32_t CurrentDownloadBitrate() const;
    uint32_t CurrentPlaybackBitrate() const;
    Windows::Foundation::Collections::IVectorView<uint32_t> AvailableBitrates() const;
    Windows::Foundation::IReference<uint32_t> DesiredMinBitrate() const;
    void DesiredMinBitrate(optional<uint32_t> const& value) const;
    Windows::Foundation::IReference<uint32_t> DesiredMaxBitrate() const;
    void DesiredMaxBitrate(optional<uint32_t> const& value) const;
    bool AudioOnlyPlayback() const;
    uint64_t InboundBitsPerSecond() const;
    Windows::Foundation::TimeSpan InboundBitsPerSecondWindow() const;
    void InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan const& value) const;
    winrt::event_token DownloadBitrateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const& handler) const;
    using DownloadBitrateChanged_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>::remove_DownloadBitrateChanged>;
    DownloadBitrateChanged_revoker DownloadBitrateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const& handler) const;
    void DownloadBitrateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PlaybackBitrateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const& handler) const;
    using PlaybackBitrateChanged_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>::remove_PlaybackBitrateChanged>;
    PlaybackBitrateChanged_revoker PlaybackBitrateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const& handler) const;
    void PlaybackBitrateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token DownloadRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const& handler) const;
    using DownloadRequested_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>::remove_DownloadRequested>;
    DownloadRequested_revoker DownloadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const& handler) const;
    void DownloadRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token DownloadCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const& handler) const;
    using DownloadCompleted_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>::remove_DownloadCompleted>;
    DownloadCompleted_revoker DownloadCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const& handler) const;
    void DownloadCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token DownloadFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const& handler) const;
    using DownloadFailed_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>::remove_DownloadFailed>;
    DownloadFailed_revoker DownloadFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const& handler) const;
    void DownloadFailed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource2
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings AdvancedSettings() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MinLiveOffset() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MaxSeekableWindowSize() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> DesiredSeekableWindowSize() const;
    void DesiredSeekableWindowSize(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics Diagnostics() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes GetCorrelatedTimes() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings
{
    bool AllSegmentsIndependent() const;
    void AllSegmentsIndependent(bool value) const;
    Windows::Foundation::IReference<double> DesiredBitrateHeadroomRatio() const;
    void DesiredBitrateHeadroomRatio(optional<double> const& value) const;
    Windows::Foundation::IReference<double> BitrateDowngradeTriggerRatio() const;
    void BitrateDowngradeTriggerRatio(optional<double> const& value) const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCorrelatedTimes
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Position() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> PresentationTimeStamp() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> ProgramDateTime() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCorrelatedTimes<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus Status() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSource MediaSource() const;
    Windows::Web::Http::HttpResponseMessage HttpResponseMessage() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType DiagnosticType() const;
    Windows::Foundation::IReference<int32_t> RequestId() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Position() const;
    Windows::Foundation::IReference<uint64_t> SegmentId() const;
    Windows::Foundation::IReference<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType> ResourceType() const;
    Windows::Foundation::Uri ResourceUri() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeOffset() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeLength() const;
    Windows::Foundation::IReference<uint32_t> Bitrate() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs2
{
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs3
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> ResourceDuration() const;
    hstring ResourceContentType() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs3<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics
{
    winrt::event_token DiagnosticAvailable(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const& handler) const;
    using DiagnosticAvailable_revoker = impl::event_revoker<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics, &impl::abi_t<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>::remove_DiagnosticAvailable>;
    DiagnosticAvailable_revoker DiagnosticAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const& handler) const;
    void DiagnosticAvailable(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs
{
    uint32_t OldValue() const;
    uint32_t NewValue() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason Reason() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType ResourceType() const;
    Windows::Foundation::Uri ResourceUri() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeOffset() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeLength() const;
    Windows::Web::Http::HttpResponseMessage HttpResponseMessage() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs2
{
    int32_t RequestId() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics Statistics() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Position() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs3
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> ResourceDuration() const;
    hstring ResourceContentType() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs3<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType ResourceType() const;
    Windows::Foundation::Uri ResourceUri() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeOffset() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeLength() const;
    Windows::Web::Http::HttpResponseMessage HttpResponseMessage() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2
{
    int32_t RequestId() const;
    winrt::hresult ExtendedError() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics Statistics() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Position() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs3
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> ResourceDuration() const;
    hstring ResourceContentType() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs3<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedDeferral<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType ResourceType() const;
    Windows::Foundation::Uri ResourceUri() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeOffset() const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeLength() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult Result() const;
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs2
{
    int32_t RequestId() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Position() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs3
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> ResourceDuration() const;
    hstring ResourceContentType() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs3<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult
{
    Windows::Foundation::Uri ResourceUri() const;
    void ResourceUri(Windows::Foundation::Uri const& value) const;
    Windows::Storage::Streams::IInputStream InputStream() const;
    void InputStream(Windows::Storage::Streams::IInputStream const& value) const;
    Windows::Storage::Streams::IBuffer Buffer() const;
    void Buffer(Windows::Storage::Streams::IBuffer const& value) const;
    hstring ContentType() const;
    void ContentType(param::hstring const& value) const;
    uint32_t ExtendedStatus() const;
    void ExtendedStatus(uint32_t value) const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2
{
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeOffset() const;
    void ResourceByteRangeOffset(optional<uint64_t> const& value) const;
    Windows::Foundation::IReference<uint64_t> ResourceByteRangeLength() const;
    void ResourceByteRangeLength(optional<uint64_t> const& value) const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics
{
    uint64_t ContentBytesReceivedCount() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> TimeToHeadersReceived() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> TimeToFirstByteReceived() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> TimeToLastByteReceived() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs
{
    uint32_t OldValue() const;
    uint32_t NewValue() const;
    bool AudioOnly() const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics
{
    bool IsContentTypeSupported(param::hstring const& contentType) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> CreateFromUriAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> CreateFromUriAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpClient const& httpClient) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType, Windows::Web::Http::HttpClient const& httpClient) const;
};
template <> struct consume<Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics> { template <typename D> using type = consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>; };

}
