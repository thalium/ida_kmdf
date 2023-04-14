// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;
struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct IDirect3DSurface;

}

WINRT_EXPORT namespace winrt::Windows::Media {

enum class MediaPlaybackAutoRepeatMode;
enum class MediaPlaybackType;
struct MediaTimeRange;
struct MediaTimelineController;
struct MusicDisplayProperties;
struct SystemMediaTransportControls;
struct VideoDisplayProperties;

}

WINRT_EXPORT namespace winrt::Windows::Media::Audio {

struct AudioStateMonitor;

}

WINRT_EXPORT namespace winrt::Windows::Media::Casting {

struct CastingSource;

}

WINRT_EXPORT namespace winrt::Windows::Media::Core {

struct AudioTrack;
struct IMediaSource;
struct ISingleSelectMediaTrackList;
struct MediaSource;
struct TimedMetadataTrack;
struct VideoTrack;

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

enum class MediaRotation;
enum class SphericalVideoFrameFormat;
enum class StereoscopicVideoPackingMode;

}

WINRT_EXPORT namespace winrt::Windows::Media::Protection {

struct MediaProtectionManager;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;
struct RandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct Compositor;
struct ICompositionSurface;

}

WINRT_EXPORT namespace winrt::Windows::Media::Playback {

enum class AutoLoadedDisplayPropertyKind : int32_t
{
    None = 0,
    MusicOrVideo = 1,
    Music = 2,
    Video = 3,
};

enum class FailedMediaStreamKind : int32_t
{
    Unknown = 0,
    Audio = 1,
    Video = 2,
};

enum class MediaBreakInsertionMethod : int32_t
{
    Interrupt = 0,
    Replace = 1,
};

enum class MediaCommandEnablingRule : int32_t
{
    Auto = 0,
    Always = 1,
    Never = 2,
};

enum class MediaPlaybackItemChangedReason : int32_t
{
    InitialItem = 0,
    EndOfStream = 1,
    Error = 2,
    AppRequested = 3,
};

enum class MediaPlaybackItemErrorCode : int32_t
{
    None = 0,
    Aborted = 1,
    NetworkError = 2,
    DecodeError = 3,
    SourceNotSupportedError = 4,
    EncryptionError = 5,
};

enum class MediaPlaybackSessionVideoConstrictionReason : int32_t
{
    None = 0,
    VirtualMachine = 1,
    UnsupportedDisplayAdapter = 2,
    UnsignedDriver = 3,
    FrameServerEnabled = 4,
    OutputProtectionFailed = 5,
    Unknown = 6,
};

enum class MediaPlaybackState : int32_t
{
    None = 0,
    Opening = 1,
    Buffering = 2,
    Playing = 3,
    Paused = 4,
};

enum class MediaPlayerAudioCategory : int32_t
{
    Other = 0,
    Communications = 3,
    Alerts = 4,
    SoundEffects = 5,
    GameEffects = 6,
    GameMedia = 7,
    GameChat = 8,
    Speech = 9,
    Movie = 10,
    Media = 11,
};

enum class MediaPlayerAudioDeviceType : int32_t
{
    Console = 0,
    Multimedia = 1,
    Communications = 2,
};

enum class MediaPlayerError : int32_t
{
    Unknown = 0,
    Aborted = 1,
    NetworkError = 2,
    DecodingError = 3,
    SourceNotSupported = 4,
};

enum class MediaPlayerState : int32_t
{
    Closed = 0,
    Opening = 1,
    Buffering = 2,
    Playing = 3,
    Paused = 4,
    Stopped = 5,
};

enum class SphericalVideoProjectionMode : int32_t
{
    Spherical = 0,
    Flat = 1,
};

enum class StereoscopicVideoRenderMode : int32_t
{
    Mono = 0,
    Stereo = 1,
};

enum class TimedMetadataTrackPresentationMode : int32_t
{
    Disabled = 0,
    Hidden = 1,
    ApplicationPresented = 2,
    PlatformPresented = 3,
};

struct IBackgroundMediaPlayerStatics;
struct ICurrentMediaPlaybackItemChangedEventArgs;
struct ICurrentMediaPlaybackItemChangedEventArgs2;
struct IMediaBreak;
struct IMediaBreakEndedEventArgs;
struct IMediaBreakFactory;
struct IMediaBreakManager;
struct IMediaBreakSchedule;
struct IMediaBreakSeekedOverEventArgs;
struct IMediaBreakSkippedEventArgs;
struct IMediaBreakStartedEventArgs;
struct IMediaEnginePlaybackSource;
struct IMediaItemDisplayProperties;
struct IMediaPlaybackCommandManager;
struct IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs;
struct IMediaPlaybackCommandManagerCommandBehavior;
struct IMediaPlaybackCommandManagerFastForwardReceivedEventArgs;
struct IMediaPlaybackCommandManagerNextReceivedEventArgs;
struct IMediaPlaybackCommandManagerPauseReceivedEventArgs;
struct IMediaPlaybackCommandManagerPlayReceivedEventArgs;
struct IMediaPlaybackCommandManagerPositionReceivedEventArgs;
struct IMediaPlaybackCommandManagerPreviousReceivedEventArgs;
struct IMediaPlaybackCommandManagerRateReceivedEventArgs;
struct IMediaPlaybackCommandManagerRewindReceivedEventArgs;
struct IMediaPlaybackCommandManagerShuffleReceivedEventArgs;
struct IMediaPlaybackItem;
struct IMediaPlaybackItem2;
struct IMediaPlaybackItem3;
struct IMediaPlaybackItemError;
struct IMediaPlaybackItemFactory;
struct IMediaPlaybackItemFactory2;
struct IMediaPlaybackItemFailedEventArgs;
struct IMediaPlaybackItemOpenedEventArgs;
struct IMediaPlaybackItemStatics;
struct IMediaPlaybackList;
struct IMediaPlaybackList2;
struct IMediaPlaybackList3;
struct IMediaPlaybackSession;
struct IMediaPlaybackSession2;
struct IMediaPlaybackSession3;
struct IMediaPlaybackSessionBufferingStartedEventArgs;
struct IMediaPlaybackSessionOutputDegradationPolicyState;
struct IMediaPlaybackSource;
struct IMediaPlaybackSphericalVideoProjection;
struct IMediaPlaybackTimedMetadataTrackList;
struct IMediaPlayer;
struct IMediaPlayer2;
struct IMediaPlayer3;
struct IMediaPlayer4;
struct IMediaPlayer5;
struct IMediaPlayer6;
struct IMediaPlayer7;
struct IMediaPlayerDataReceivedEventArgs;
struct IMediaPlayerEffects;
struct IMediaPlayerEffects2;
struct IMediaPlayerFailedEventArgs;
struct IMediaPlayerRateChangedEventArgs;
struct IMediaPlayerSource;
struct IMediaPlayerSource2;
struct IMediaPlayerSurface;
struct IPlaybackMediaMarker;
struct IPlaybackMediaMarkerFactory;
struct IPlaybackMediaMarkerReachedEventArgs;
struct IPlaybackMediaMarkerSequence;
struct ITimedMetadataPresentationModeChangedEventArgs;
struct BackgroundMediaPlayer;
struct CurrentMediaPlaybackItemChangedEventArgs;
struct MediaBreak;
struct MediaBreakEndedEventArgs;
struct MediaBreakManager;
struct MediaBreakSchedule;
struct MediaBreakSeekedOverEventArgs;
struct MediaBreakSkippedEventArgs;
struct MediaBreakStartedEventArgs;
struct MediaItemDisplayProperties;
struct MediaPlaybackAudioTrackList;
struct MediaPlaybackCommandManager;
struct MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs;
struct MediaPlaybackCommandManagerCommandBehavior;
struct MediaPlaybackCommandManagerFastForwardReceivedEventArgs;
struct MediaPlaybackCommandManagerNextReceivedEventArgs;
struct MediaPlaybackCommandManagerPauseReceivedEventArgs;
struct MediaPlaybackCommandManagerPlayReceivedEventArgs;
struct MediaPlaybackCommandManagerPositionReceivedEventArgs;
struct MediaPlaybackCommandManagerPreviousReceivedEventArgs;
struct MediaPlaybackCommandManagerRateReceivedEventArgs;
struct MediaPlaybackCommandManagerRewindReceivedEventArgs;
struct MediaPlaybackCommandManagerShuffleReceivedEventArgs;
struct MediaPlaybackItem;
struct MediaPlaybackItemError;
struct MediaPlaybackItemFailedEventArgs;
struct MediaPlaybackItemOpenedEventArgs;
struct MediaPlaybackList;
struct MediaPlaybackSession;
struct MediaPlaybackSessionBufferingStartedEventArgs;
struct MediaPlaybackSessionOutputDegradationPolicyState;
struct MediaPlaybackSphericalVideoProjection;
struct MediaPlaybackTimedMetadataTrackList;
struct MediaPlaybackVideoTrackList;
struct MediaPlayer;
struct MediaPlayerDataReceivedEventArgs;
struct MediaPlayerFailedEventArgs;
struct MediaPlayerRateChangedEventArgs;
struct MediaPlayerSurface;
struct PlaybackMediaMarker;
struct PlaybackMediaMarkerReachedEventArgs;
struct PlaybackMediaMarkerSequence;
struct TimedMetadataPresentationModeChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Playback::IBackgroundMediaPlayerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreak>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakEndedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakSchedule>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakSkippedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaBreakStartedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaEnginePlaybackSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaItemDisplayProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItem>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItem2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItem3>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemError>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemFactory2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackItemStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackList>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackList2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackList3>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSession>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSession2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSession3>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer3>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer4>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer5>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer6>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayer7>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerEffects>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerEffects2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerFailedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerSource2>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IMediaPlayerSurface>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IPlaybackMediaMarker>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IPlaybackMediaMarkerFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::IPlaybackMediaMarkerSequence>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Playback::BackgroundMediaPlayer>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreak>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakEndedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakManager>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakSchedule>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakSeekedOverEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakSkippedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaBreakStartedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaItemDisplayProperties>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackAudioTrackList>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManager>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItem>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItemError>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItemFailedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackList>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackSession>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackSphericalVideoProjection>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackVideoTrackList>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlayer>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerFailedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerRateChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerSurface>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::PlaybackMediaMarker>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::PlaybackMediaMarkerSequence>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Playback::AutoLoadedDisplayPropertyKind>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::FailedMediaStreamKind>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaBreakInsertionMethod>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaCommandEnablingRule>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItemChangedReason>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackItemErrorCode>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlaybackState>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerAudioCategory>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerAudioDeviceType>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerError>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::MediaPlayerState>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::SphericalVideoProjectionMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::StereoscopicVideoRenderMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Playback::TimedMetadataTrackPresentationMode>{ using type = enum_category; };
template <> struct name<Windows::Media::Playback::IBackgroundMediaPlayerStatics>{ static constexpr auto & value{ L"Windows.Media.Playback.IBackgroundMediaPlayerStatics" }; };
template <> struct name<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.ICurrentMediaPlaybackItemChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>{ static constexpr auto & value{ L"Windows.Media.Playback.ICurrentMediaPlaybackItemChangedEventArgs2" }; };
template <> struct name<Windows::Media::Playback::IMediaBreak>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreak" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakEndedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakEndedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakFactory>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakFactory" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakManager>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakManager" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakSchedule>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakSchedule" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakSeekedOverEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakSkippedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakSkippedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaBreakStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaBreakStartedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaEnginePlaybackSource>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaEnginePlaybackSource" }; };
template <> struct name<Windows::Media::Playback::IMediaItemDisplayProperties>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaItemDisplayProperties" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManager>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManager" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerCommandBehavior" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerFastForwardReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerNextReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerPauseReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerPlayReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerPositionReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerPreviousReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerRateReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerRewindReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackCommandManagerShuffleReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItem>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItem" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItem2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItem2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItem3>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItem3" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemError>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemError" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemFactory>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemFactory" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemFactory2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemFactory2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemFailedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemOpenedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackItemStatics>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackItemStatics" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackList>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackList" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackList2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackList2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackList3>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackList3" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSession>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSession" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSession2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSession2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSession3>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSession3" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSessionBufferingStartedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSessionOutputDegradationPolicyState" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSource>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSource" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackSphericalVideoProjection" }; };
template <> struct name<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlaybackTimedMetadataTrackList" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer3>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer3" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer4>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer4" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer5>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer5" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer6>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer6" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayer7>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayer7" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerDataReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerEffects>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerEffects" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerEffects2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerEffects2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerFailedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerRateChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerSource>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerSource" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerSource2>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerSource2" }; };
template <> struct name<Windows::Media::Playback::IMediaPlayerSurface>{ static constexpr auto & value{ L"Windows.Media.Playback.IMediaPlayerSurface" }; };
template <> struct name<Windows::Media::Playback::IPlaybackMediaMarker>{ static constexpr auto & value{ L"Windows.Media.Playback.IPlaybackMediaMarker" }; };
template <> struct name<Windows::Media::Playback::IPlaybackMediaMarkerFactory>{ static constexpr auto & value{ L"Windows.Media.Playback.IPlaybackMediaMarkerFactory" }; };
template <> struct name<Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.IPlaybackMediaMarkerReachedEventArgs" }; };
template <> struct name<Windows::Media::Playback::IPlaybackMediaMarkerSequence>{ static constexpr auto & value{ L"Windows.Media.Playback.IPlaybackMediaMarkerSequence" }; };
template <> struct name<Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.ITimedMetadataPresentationModeChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::BackgroundMediaPlayer>{ static constexpr auto & value{ L"Windows.Media.Playback.BackgroundMediaPlayer" }; };
template <> struct name<Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.CurrentMediaPlaybackItemChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaBreak>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreak" }; };
template <> struct name<Windows::Media::Playback::MediaBreakEndedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakEndedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaBreakManager>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakManager" }; };
template <> struct name<Windows::Media::Playback::MediaBreakSchedule>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakSchedule" }; };
template <> struct name<Windows::Media::Playback::MediaBreakSeekedOverEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakSeekedOverEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaBreakSkippedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakSkippedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaBreakStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakStartedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaItemDisplayProperties>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaItemDisplayProperties" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackAudioTrackList>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackAudioTrackList" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManager>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManager" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerCommandBehavior" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerFastForwardReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerNextReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerPauseReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerPlayReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerPositionReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerPreviousReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerRateReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerRewindReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackCommandManagerShuffleReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItem>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItem" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItemError>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItemError" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItemFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItemFailedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItemOpenedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackList>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackList" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackSession>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackSession" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackSessionBufferingStartedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackSessionOutputDegradationPolicyState" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackSphericalVideoProjection>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackSphericalVideoProjection" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackTimedMetadataTrackList" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackVideoTrackList>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackVideoTrackList" }; };
template <> struct name<Windows::Media::Playback::MediaPlayer>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayer" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerDataReceivedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerFailedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerFailedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerRateChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerRateChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerSurface>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerSurface" }; };
template <> struct name<Windows::Media::Playback::PlaybackMediaMarker>{ static constexpr auto & value{ L"Windows.Media.Playback.PlaybackMediaMarker" }; };
template <> struct name<Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.PlaybackMediaMarkerReachedEventArgs" }; };
template <> struct name<Windows::Media::Playback::PlaybackMediaMarkerSequence>{ static constexpr auto & value{ L"Windows.Media.Playback.PlaybackMediaMarkerSequence" }; };
template <> struct name<Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Playback.TimedMetadataPresentationModeChangedEventArgs" }; };
template <> struct name<Windows::Media::Playback::AutoLoadedDisplayPropertyKind>{ static constexpr auto & value{ L"Windows.Media.Playback.AutoLoadedDisplayPropertyKind" }; };
template <> struct name<Windows::Media::Playback::FailedMediaStreamKind>{ static constexpr auto & value{ L"Windows.Media.Playback.FailedMediaStreamKind" }; };
template <> struct name<Windows::Media::Playback::MediaBreakInsertionMethod>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaBreakInsertionMethod" }; };
template <> struct name<Windows::Media::Playback::MediaCommandEnablingRule>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaCommandEnablingRule" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItemChangedReason>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItemChangedReason" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackItemErrorCode>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackItemErrorCode" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackSessionVideoConstrictionReason" }; };
template <> struct name<Windows::Media::Playback::MediaPlaybackState>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlaybackState" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerAudioCategory>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerAudioCategory" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerAudioDeviceType>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerAudioDeviceType" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerError>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerError" }; };
template <> struct name<Windows::Media::Playback::MediaPlayerState>{ static constexpr auto & value{ L"Windows.Media.Playback.MediaPlayerState" }; };
template <> struct name<Windows::Media::Playback::SphericalVideoProjectionMode>{ static constexpr auto & value{ L"Windows.Media.Playback.SphericalVideoProjectionMode" }; };
template <> struct name<Windows::Media::Playback::StereoscopicVideoRenderMode>{ static constexpr auto & value{ L"Windows.Media.Playback.StereoscopicVideoRenderMode" }; };
template <> struct name<Windows::Media::Playback::TimedMetadataTrackPresentationMode>{ static constexpr auto & value{ L"Windows.Media.Playback.TimedMetadataTrackPresentationMode" }; };
template <> struct guid_storage<Windows::Media::Playback::IBackgroundMediaPlayerStatics>{ static constexpr guid value{ 0x856DDBC1,0x55F7,0x471F,{ 0xA0,0xF2,0x68,0xAC,0x4C,0x90,0x45,0x92 } }; };
template <> struct guid_storage<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>{ static constexpr guid value{ 0x1743A892,0x5C43,0x4A15,{ 0x96,0x7A,0x57,0x2D,0x2D,0x0F,0x26,0xC6 } }; };
template <> struct guid_storage<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>{ static constexpr guid value{ 0x1D80A51E,0x996E,0x40A9,{ 0xBE,0x48,0xE6,0x6E,0xC9,0x0B,0x2B,0x7D } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreak>{ static constexpr guid value{ 0x714BE270,0x0DEF,0x4EBC,{ 0xA4,0x89,0x6B,0x34,0x93,0x0E,0x15,0x58 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakEndedEventArgs>{ static constexpr guid value{ 0x32B93276,0x1C5D,0x4FEE,{ 0x87,0x32,0x23,0x6D,0xC3,0xA8,0x85,0x80 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakFactory>{ static constexpr guid value{ 0x4516E002,0x18E0,0x4079,{ 0x8B,0x5F,0xD3,0x34,0x95,0xC1,0x5D,0x2E } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakManager>{ static constexpr guid value{ 0xA854DDB1,0xFEB4,0x4D9B,{ 0x9D,0x97,0x0F,0xDB,0xE5,0x8E,0x5E,0x39 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakSchedule>{ static constexpr guid value{ 0xA19A5813,0x98B6,0x41D8,{ 0x83,0xDA,0xF9,0x71,0xD2,0x2B,0x7B,0xBA } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>{ static constexpr guid value{ 0xE5AA6746,0x0606,0x4492,{ 0xB9,0xD3,0xC3,0xC8,0xFD,0xE0,0xA4,0xEA } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakSkippedEventArgs>{ static constexpr guid value{ 0x6EE94C05,0x2F54,0x4A3E,{ 0xA3,0xAB,0x24,0xC3,0xB2,0x70,0xB4,0xA3 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaBreakStartedEventArgs>{ static constexpr guid value{ 0xA87EFE71,0xDFD4,0x454A,{ 0x95,0x6E,0x0A,0x4A,0x64,0x83,0x95,0xF8 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaEnginePlaybackSource>{ static constexpr guid value{ 0x5C1D0BA7,0x3856,0x48B9,{ 0x8D,0xC6,0x24,0x4B,0xF1,0x07,0xBF,0x8C } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaItemDisplayProperties>{ static constexpr guid value{ 0x1E3C1B48,0x7097,0x4384,{ 0xA2,0x17,0xC1,0x29,0x1D,0xFA,0x8C,0x16 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManager>{ static constexpr guid value{ 0x5ACEE5A6,0x5CB6,0x4A5A,{ 0x85,0x21,0xCC,0x86,0xB1,0xC1,0xED,0x37 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ static constexpr guid value{ 0x3D6F4F23,0x5230,0x4411,{ 0xA0,0xE9,0xBA,0xD9,0x4C,0x2A,0x04,0x5C } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>{ static constexpr guid value{ 0x786C1E78,0xCE78,0x4A10,{ 0xAF,0xD6,0x84,0x3F,0xCB,0xB9,0x0C,0x2E } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ static constexpr guid value{ 0x30F064D9,0xB491,0x4D0A,{ 0xBC,0x21,0x30,0x98,0xBD,0x13,0x32,0xE9 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>{ static constexpr guid value{ 0xE1504433,0xA2B0,0x45D4,{ 0xB9,0xDE,0x5F,0x42,0xAC,0x14,0xA8,0x39 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>{ static constexpr guid value{ 0x5CECCD1C,0xC25C,0x4221,{ 0xB1,0x6C,0xC3,0xC9,0x8C,0xE0,0x12,0xD6 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>{ static constexpr guid value{ 0x9AF0004E,0x578B,0x4C56,{ 0xA0,0x06,0x16,0x15,0x9D,0x88,0x8A,0x48 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>{ static constexpr guid value{ 0x5591A754,0xD627,0x4BDD,{ 0xA9,0x0D,0x86,0xA0,0x15,0xB2,0x49,0x02 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>{ static constexpr guid value{ 0x525E3081,0x4632,0x4F76,{ 0x99,0xB1,0xD7,0x71,0x62,0x3F,0x62,0x87 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>{ static constexpr guid value{ 0x18EA3939,0x4A16,0x4169,{ 0x8B,0x05,0x3E,0xB9,0xF5,0xFF,0x78,0xEB } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>{ static constexpr guid value{ 0x9F085947,0xA3C0,0x425D,{ 0xAA,0xEF,0x97,0xBA,0x78,0x98,0xB1,0x41 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>{ static constexpr guid value{ 0x50A05CEF,0x63EE,0x4A96,{ 0xB7,0xB5,0xFE,0xE0,0x8B,0x9F,0xF9,0x0C } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItem>{ static constexpr guid value{ 0x047097D2,0xE4AF,0x48AB,{ 0xB2,0x83,0x69,0x29,0xE6,0x74,0xEC,0xE2 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItem2>{ static constexpr guid value{ 0xD859D171,0xD7EF,0x4B81,{ 0xAC,0x1F,0xF4,0x04,0x93,0xCB,0xB0,0x91 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItem3>{ static constexpr guid value{ 0x0D328220,0xB80A,0x4D09,{ 0x9F,0xF8,0xF8,0x70,0x94,0xA1,0xC8,0x31 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemError>{ static constexpr guid value{ 0x69FBEF2B,0xDCD6,0x4DF9,{ 0xA4,0x50,0xDB,0xF4,0xC6,0xF1,0xC2,0xC2 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemFactory>{ static constexpr guid value{ 0x7133FCE1,0x1769,0x4FF9,{ 0xA7,0xC1,0x38,0xD2,0xC4,0xD4,0x23,0x60 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemFactory2>{ static constexpr guid value{ 0xD77CDF3A,0xB947,0x4972,{ 0xB3,0x5D,0xAD,0xFB,0x93,0x1A,0x71,0xE6 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>{ static constexpr guid value{ 0x7703134A,0xE9A7,0x47C3,{ 0x86,0x2C,0xC6,0x56,0xD3,0x06,0x83,0xD4 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>{ static constexpr guid value{ 0xCBD9BD82,0x3037,0x4FBE,{ 0xAE,0x8F,0x39,0xFC,0x39,0xED,0xF4,0xEF } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackItemStatics>{ static constexpr guid value{ 0x4B1BE7F4,0x4345,0x403C,{ 0x8A,0x67,0xF5,0xDE,0x91,0xDF,0x4C,0x86 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackList>{ static constexpr guid value{ 0x7F77EE9C,0xDC42,0x4E26,{ 0xA9,0x8D,0x78,0x50,0xDF,0x8E,0xC9,0x25 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackList2>{ static constexpr guid value{ 0x0E09B478,0x600A,0x4274,{ 0xA1,0x4B,0x0B,0x67,0x23,0xD0,0xF4,0x8B } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackList3>{ static constexpr guid value{ 0xDD24BBA9,0xBC47,0x4463,{ 0xAA,0x90,0xC1,0x8B,0x7E,0x5F,0xFD,0xE1 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSession>{ static constexpr guid value{ 0xC32B683D,0x0407,0x41BA,{ 0x89,0x46,0x8B,0x34,0x5A,0x5A,0x54,0x35 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSession2>{ static constexpr guid value{ 0xF8BA7C79,0x1FC8,0x4097,{ 0xAD,0x70,0xC0,0xFA,0x18,0xCC,0x00,0x50 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSession3>{ static constexpr guid value{ 0x7BA2B41A,0xA3E2,0x405F,{ 0xB7,0x7B,0xA4,0x81,0x2C,0x23,0x8B,0x66 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>{ static constexpr guid value{ 0xCD6AAFED,0x74E2,0x43B5,{ 0xB1,0x15,0x76,0x23,0x6C,0x33,0x79,0x1A } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>{ static constexpr guid value{ 0x558E727D,0xF633,0x49F9,{ 0x96,0x5A,0xAB,0xAA,0x1D,0xB7,0x09,0xBE } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSource>{ static constexpr guid value{ 0xEF9DC2BC,0x9317,0x4696,{ 0xB0,0x51,0x2B,0xAD,0x64,0x31,0x77,0xB5 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>{ static constexpr guid value{ 0xD405B37C,0x6F0E,0x4661,{ 0xB8,0xEE,0xD4,0x87,0xBA,0x97,0x52,0xD5 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>{ static constexpr guid value{ 0x72B41319,0xBBFB,0x46A3,{ 0x93,0x72,0x9C,0x9C,0x74,0x4B,0x94,0x38 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer>{ static constexpr guid value{ 0x381A83CB,0x6FFF,0x499B,{ 0x8D,0x64,0x28,0x85,0xDF,0xC1,0x24,0x9E } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer2>{ static constexpr guid value{ 0x3C841218,0x2123,0x4FC5,{ 0x90,0x82,0x2F,0x88,0x3F,0x77,0xBD,0xF5 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer3>{ static constexpr guid value{ 0xEE0660DA,0x031B,0x4FEB,{ 0xBD,0x9B,0x92,0xE0,0xA0,0xA8,0xD2,0x99 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer4>{ static constexpr guid value{ 0x80035DB0,0x7448,0x4770,{ 0xAF,0xCF,0x2A,0x57,0x45,0x09,0x14,0xC5 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer5>{ static constexpr guid value{ 0xCFE537FD,0xF86A,0x4446,{ 0xBF,0x4D,0xC8,0xE7,0x92,0xB7,0xB4,0xB3 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer6>{ static constexpr guid value{ 0xE0CAA086,0xAE65,0x414C,{ 0xB0,0x10,0x8B,0xC5,0x5F,0x00,0xE6,0x92 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayer7>{ static constexpr guid value{ 0x5D1DC478,0x4500,0x4531,{ 0xB3,0xF4,0x77,0x7A,0x71,0x49,0x1F,0x7F } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>{ static constexpr guid value{ 0xC75A9405,0xC801,0x412A,{ 0x83,0x5B,0x83,0xFC,0x0E,0x62,0x2A,0x8E } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerEffects>{ static constexpr guid value{ 0x85A1DEDA,0xCAB6,0x4CC0,{ 0x8B,0xE3,0x60,0x35,0xF4,0xDE,0x25,0x91 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerEffects2>{ static constexpr guid value{ 0xFA419A79,0x1BBE,0x46C5,{ 0xAE,0x1F,0x8E,0xE6,0x9F,0xB3,0xC2,0xC7 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerFailedEventArgs>{ static constexpr guid value{ 0x2744E9B9,0xA7E3,0x4F16,{ 0xBA,0xC4,0x79,0x14,0xEB,0xC0,0x83,0x01 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>{ static constexpr guid value{ 0x40600D58,0x3B61,0x4BB2,{ 0x98,0x9F,0xFC,0x65,0x60,0x8B,0x6C,0xAB } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerSource>{ static constexpr guid value{ 0xBD4F8897,0x1423,0x4C3E,{ 0x82,0xC5,0x0F,0xB1,0xAF,0x94,0xF7,0x15 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerSource2>{ static constexpr guid value{ 0x82449B9F,0x7322,0x4C0B,{ 0xB0,0x3B,0x3E,0x69,0xA4,0x82,0x60,0xC5 } }; };
template <> struct guid_storage<Windows::Media::Playback::IMediaPlayerSurface>{ static constexpr guid value{ 0x0ED653BC,0xB736,0x49C3,{ 0x83,0x0B,0x76,0x4A,0x38,0x45,0x31,0x3A } }; };
template <> struct guid_storage<Windows::Media::Playback::IPlaybackMediaMarker>{ static constexpr guid value{ 0xC4D22F5C,0x3C1C,0x4444,{ 0xB6,0xB9,0x77,0x8B,0x04,0x22,0xD4,0x1A } }; };
template <> struct guid_storage<Windows::Media::Playback::IPlaybackMediaMarkerFactory>{ static constexpr guid value{ 0x8C530A78,0xE0AE,0x4E1A,{ 0xA8,0xC8,0xE2,0x3F,0x98,0x2A,0x93,0x7B } }; };
template <> struct guid_storage<Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>{ static constexpr guid value{ 0x578CD1B9,0x90E2,0x4E60,{ 0xAB,0xC4,0x87,0x40,0xB0,0x1F,0x61,0x96 } }; };
template <> struct guid_storage<Windows::Media::Playback::IPlaybackMediaMarkerSequence>{ static constexpr guid value{ 0xF2810CEE,0x638B,0x46CF,{ 0x88,0x17,0x1D,0x11,0x1F,0xE9,0xD8,0xC4 } }; };
template <> struct guid_storage<Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>{ static constexpr guid value{ 0xD1636099,0x65DF,0x45AE,{ 0x8C,0xEF,0xDC,0x0B,0x53,0xFD,0xC2,0xBB } }; };
template <> struct default_interface<Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs>{ using type = Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaBreak>{ using type = Windows::Media::Playback::IMediaBreak; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakEndedEventArgs>{ using type = Windows::Media::Playback::IMediaBreakEndedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakManager>{ using type = Windows::Media::Playback::IMediaBreakManager; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakSchedule>{ using type = Windows::Media::Playback::IMediaBreakSchedule; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakSeekedOverEventArgs>{ using type = Windows::Media::Playback::IMediaBreakSeekedOverEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakSkippedEventArgs>{ using type = Windows::Media::Playback::IMediaBreakSkippedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaBreakStartedEventArgs>{ using type = Windows::Media::Playback::IMediaBreakStartedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaItemDisplayProperties>{ using type = Windows::Media::Playback::IMediaItemDisplayProperties; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackAudioTrackList>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Media::Core::AudioTrack>; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManager>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManager; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackItem>{ using type = Windows::Media::Playback::IMediaPlaybackItem; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackItemError>{ using type = Windows::Media::Playback::IMediaPlaybackItemError; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackItemFailedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackList>{ using type = Windows::Media::Playback::IMediaPlaybackList; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackSession>{ using type = Windows::Media::Playback::IMediaPlaybackSession; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs>{ using type = Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState>{ using type = Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackSphericalVideoProjection>{ using type = Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack>; };
template <> struct default_interface<Windows::Media::Playback::MediaPlaybackVideoTrackList>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Media::Core::VideoTrack>; };
template <> struct default_interface<Windows::Media::Playback::MediaPlayer>{ using type = Windows::Media::Playback::IMediaPlayer; };
template <> struct default_interface<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs>{ using type = Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlayerFailedEventArgs>{ using type = Windows::Media::Playback::IMediaPlayerFailedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlayerRateChangedEventArgs>{ using type = Windows::Media::Playback::IMediaPlayerRateChangedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::MediaPlayerSurface>{ using type = Windows::Media::Playback::IMediaPlayerSurface; };
template <> struct default_interface<Windows::Media::Playback::PlaybackMediaMarker>{ using type = Windows::Media::Playback::IPlaybackMediaMarker; };
template <> struct default_interface<Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs>{ using type = Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs; };
template <> struct default_interface<Windows::Media::Playback::PlaybackMediaMarkerSequence>{ using type = Windows::Media::Playback::IPlaybackMediaMarkerSequence; };
template <> struct default_interface<Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs>{ using type = Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs; };

template <> struct abi<Windows::Media::Playback::IBackgroundMediaPlayerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** player) noexcept = 0;
    virtual int32_t WINRT_CALL add_MessageReceivedFromBackground(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MessageReceivedFromBackground(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MessageReceivedFromForeground(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MessageReceivedFromForeground(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL SendMessageToBackground(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SendMessageToForeground(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsMediaPlaying(bool* isMediaPlaying) noexcept = 0;
    virtual int32_t WINRT_CALL Shutdown() noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NewItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OldItem(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Reason(Windows::Media::Playback::MediaPlaybackItemChangedReason* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreak>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PlaybackList(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationPosition(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InsertionMethod(Windows::Media::Playback::MediaBreakInsertionMethod* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanStart(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CanStart(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakEndedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MediaBreak(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Media::Playback::MediaBreakInsertionMethod insertionMethod, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithPresentationPosition(Windows::Media::Playback::MediaBreakInsertionMethod insertionMethod, Windows::Foundation::TimeSpan presentationPosition, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_BreaksSeekedOver(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BreaksSeekedOver(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BreakStarted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BreakStarted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BreakEnded(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BreakEnded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BreakSkipped(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BreakSkipped(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentBreak(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackSession(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL PlayBreak(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SkipCurrentBreak() noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakSchedule>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ScheduleChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ScheduleChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL InsertMidrollBreak(void* mediaBreak) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveMidrollBreak(void* mediaBreak) noexcept = 0;
    virtual int32_t WINRT_CALL get_MidrollBreaks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PrerollBreak(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrerollBreak(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PostrollBreak(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PostrollBreak(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackItem(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SeekedOverBreaks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OldPosition(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewPosition(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakSkippedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MediaBreak(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaBreakStartedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MediaBreak(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaEnginePlaybackSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CurrentItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPlaybackSource(void* source) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaItemDisplayProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Type(Windows::Media::MediaPlaybackType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Type(Windows::Media::MediaPlaybackType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MusicProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL ClearAll() noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlayBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PauseBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NextBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreviousBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FastForwardBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RewindBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShuffleBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoRepeatModeBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PositionBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RateBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlayReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlayReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PauseReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PauseReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_NextReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NextReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PreviousReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PreviousReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_FastForwardReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FastForwardReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RewindReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RewindReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ShuffleReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ShuffleReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_AutoRepeatModeReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AutoRepeatModeReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PositionReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PositionReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RateReceived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RateReceived(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CommandManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule value) noexcept = 0;
    virtual int32_t WINRT_CALL add_IsEnabledChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsEnabledChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsShuffleRequested(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_AudioTracksChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AudioTracksChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_VideoTracksChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VideoTracksChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_TimedMetadataTracksChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TimedMetadataTracksChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioTracks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoTracks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimedMetadataTracks(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItem2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BreakSchedule(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DurationLimit(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanSkip(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CanSkip(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDisplayProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ApplyDisplayProperties(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItem3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsDisabledInPlaybackList(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDisabledInPlaybackList(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalDownloadProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemError>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ErrorCode(Windows::Media::Playback::MediaPlaybackItemErrorCode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* source, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemFactory2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithStartTime(void* source, Windows::Foundation::TimeSpan startTime, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithStartTimeAndDurationLimit(void* source, Windows::Foundation::TimeSpan startTime, Windows::Foundation::TimeSpan durationLimit, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Item(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Error(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Item(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackItemStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindFromMediaSource(void* source, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackList>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ItemFailed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ItemFailed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_CurrentItemChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CurrentItemChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_ItemOpened(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ItemOpened(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Items(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoRepeatEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AutoRepeatEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShuffleEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShuffleEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentItemIndex(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL MoveNext(void** item) noexcept = 0;
    virtual int32_t WINRT_CALL MovePrevious(void** item) noexcept = 0;
    virtual int32_t WINRT_CALL MoveTo(uint32_t itemIndex, void** item) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackList2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxPrefetchTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxPrefetchTime(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartingItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartingItem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShuffledItems(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetShuffledItems(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackList3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxPlayedItemsToKeepOpen(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxPlayedItemsToKeepOpen(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_PlaybackStateChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlaybackStateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlaybackRateChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlaybackRateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SeekCompleted(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SeekCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BufferingStarted(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferingStarted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BufferingEnded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferingEnded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BufferingProgressChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferingProgressChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_DownloadProgressChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_DownloadProgressChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_NaturalDurationChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NaturalDurationChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PositionChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PositionChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_NaturalVideoSizeChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_NaturalVideoSizeChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NaturalDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackState(Windows::Media::Playback::MediaPlaybackState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanSeek(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanPause(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsProtected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PlaybackRate(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BufferingProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NaturalVideoHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NaturalVideoWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NormalizedSourceRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NormalizedSourceRect(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSession2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_BufferedRangesChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferedRangesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlayedRangesChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlayedRangesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SeekableRangesChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SeekableRangesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SupportedPlaybackRatesChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SupportedPlaybackRatesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_SphericalVideoProjection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMirroring(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsMirroring(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetBufferedRanges(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPlayedRanges(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSeekableRanges(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL IsSupportedPlaybackRateRange(double rate1, double rate2, bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSession3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PlaybackRotation(Windows::Media::MediaProperties::MediaRotation* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PlaybackRotation(Windows::Media::MediaProperties::MediaRotation value) noexcept = 0;
    virtual int32_t WINRT_CALL GetOutputDegradationPolicyState(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPlaybackInterruption(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_VideoConstrictionReason(Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSource>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HorizontalFieldOfViewInDegrees(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HorizontalFieldOfViewInDegrees(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ViewOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ViewOrientation(Windows::Foundation::Numerics::quaternion value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_PresentationModeChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PresentationModeChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AutoPlay(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AutoPlay(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NaturalDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BufferingProgress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentState(Windows::Media::Playback::MediaPlayerState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanSeek(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanPause(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLoopingEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsLoopingEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsProtected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMuted(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsMuted(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PlaybackRate(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Volume(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Volume(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackMediaMarkers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaOpened(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaOpened(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaEnded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaEnded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaFailed(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaFailed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_CurrentStateChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CurrentStateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlaybackMediaMarkerReached(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlaybackMediaMarkerReached(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaPlayerRateChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaPlayerRateChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_VolumeChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VolumeChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SeekCompleted(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SeekCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BufferingStarted(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferingStarted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_BufferingEnded(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BufferingEnded(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Play() noexcept = 0;
    virtual int32_t WINRT_CALL Pause() noexcept = 0;
    virtual int32_t WINRT_CALL SetUriSource(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SystemMediaTransportControls(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_IsMutedChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsMutedChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SourceChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SourceChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioBalance(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AudioBalance(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RealTimePlayback(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RealTimePlayback(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BreakManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CommandManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AudioDevice(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AudioDevice(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimelineController(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TimelineController(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TimelineControllerPositionOffset(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TimelineControllerPositionOffset(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackSession(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL StepForwardOneFrame() noexcept = 0;
    virtual int32_t WINRT_CALL StepBackwardOneFrame() noexcept = 0;
    virtual int32_t WINRT_CALL GetAsCastingSource(void** returnValue) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetSurfaceSize(Windows::Foundation::Size size) noexcept = 0;
    virtual int32_t WINRT_CALL GetSurface(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_VideoFrameAvailable(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VideoFrameAvailable(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsVideoFrameServerEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsVideoFrameServerEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL CopyFrameToVideoSurface(void* destination) noexcept = 0;
    virtual int32_t WINRT_CALL CopyFrameToVideoSurfaceWithTargetRectangle(void* destination, Windows::Foundation::Rect targetRectangle) noexcept = 0;
    virtual int32_t WINRT_CALL CopyFrameToStereoscopicVideoSurfaces(void* destinationLeftEye, void* destinationRightEye) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer6>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_SubtitleFrameChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SubtitleFrameChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL RenderSubtitlesToSurface(void* destination, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL RenderSubtitlesToSurfaceWithTargetRectangle(void* destination, Windows::Foundation::Rect targetRectangle, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayer7>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AudioStateMonitor(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerEffects>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddAudioEffect(void* activatableClassId, bool effectOptional, void* configuration) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveAllEffects() noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerEffects2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddVideoEffect(void* activatableClassId, bool effectOptional, void* effectConfiguration) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerFailedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Media::Playback::MediaPlayerError* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorMessage(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NewRate(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProtectionManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProtectionManager(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetFileSource(void* file) noexcept = 0;
    virtual int32_t WINRT_CALL SetStreamSource(void* stream) noexcept = 0;
    virtual int32_t WINRT_CALL SetMediaSource(void* source) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerSource2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Source(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IMediaPlayerSurface>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CompositionSurface(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Compositor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IPlaybackMediaMarker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Time(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaMarkerType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IPlaybackMediaMarkerFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromTime(Windows::Foundation::TimeSpan value, void** marker) noexcept = 0;
    virtual int32_t WINRT_CALL Create(Windows::Foundation::TimeSpan value, void* mediaMarketType, void* text, void** marker) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PlaybackMediaMarker(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::IPlaybackMediaMarkerSequence>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Size(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL Insert(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL Clear() noexcept = 0;
};};

template <> struct abi<Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Track(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OldPresentationMode(Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewPresentationMode(Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics
{
    Windows::Media::Playback::MediaPlayer Current() const;
    winrt::event_token MessageReceivedFromBackground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const;
    using MessageReceivedFromBackground_revoker = impl::event_revoker<Windows::Media::Playback::IBackgroundMediaPlayerStatics, &impl::abi_t<Windows::Media::Playback::IBackgroundMediaPlayerStatics>::remove_MessageReceivedFromBackground>;
    MessageReceivedFromBackground_revoker MessageReceivedFromBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const;
    void MessageReceivedFromBackground(winrt::event_token const& token) const noexcept;
    winrt::event_token MessageReceivedFromForeground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const;
    using MessageReceivedFromForeground_revoker = impl::event_revoker<Windows::Media::Playback::IBackgroundMediaPlayerStatics, &impl::abi_t<Windows::Media::Playback::IBackgroundMediaPlayerStatics>::remove_MessageReceivedFromForeground>;
    MessageReceivedFromForeground_revoker MessageReceivedFromForeground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const;
    void MessageReceivedFromForeground(winrt::event_token const& token) const noexcept;
    void SendMessageToBackground(Windows::Foundation::Collections::ValueSet const& value) const;
    void SendMessageToForeground(Windows::Foundation::Collections::ValueSet const& value) const;
    bool IsMediaPlaying() const;
    void Shutdown() const;
};
template <> struct consume<Windows::Media::Playback::IBackgroundMediaPlayerStatics> { template <typename D> using type = consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>; };

template <typename D>
struct consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs
{
    Windows::Media::Playback::MediaPlaybackItem NewItem() const;
    Windows::Media::Playback::MediaPlaybackItem OldItem() const;
};
template <> struct consume<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs2
{
    Windows::Media::Playback::MediaPlaybackItemChangedReason Reason() const;
};
template <> struct consume<Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> { template <typename D> using type = consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreak
{
    Windows::Media::Playback::MediaPlaybackList PlaybackList() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> PresentationPosition() const;
    Windows::Media::Playback::MediaBreakInsertionMethod InsertionMethod() const;
    Windows::Foundation::Collections::ValueSet CustomProperties() const;
    bool CanStart() const;
    void CanStart(bool value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreak> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreak<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakEndedEventArgs
{
    Windows::Media::Playback::MediaBreak MediaBreak() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakEndedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakEndedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakFactory
{
    Windows::Media::Playback::MediaBreak Create(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod) const;
    Windows::Media::Playback::MediaBreak CreateWithPresentationPosition(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod, Windows::Foundation::TimeSpan const& presentationPosition) const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakFactory> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakFactory<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakManager
{
    winrt::event_token BreaksSeekedOver(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const;
    using BreaksSeekedOver_revoker = impl::event_revoker<Windows::Media::Playback::IMediaBreakManager, &impl::abi_t<Windows::Media::Playback::IMediaBreakManager>::remove_BreaksSeekedOver>;
    BreaksSeekedOver_revoker BreaksSeekedOver(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const;
    void BreaksSeekedOver(winrt::event_token const& token) const noexcept;
    winrt::event_token BreakStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const;
    using BreakStarted_revoker = impl::event_revoker<Windows::Media::Playback::IMediaBreakManager, &impl::abi_t<Windows::Media::Playback::IMediaBreakManager>::remove_BreakStarted>;
    BreakStarted_revoker BreakStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const;
    void BreakStarted(winrt::event_token const& token) const noexcept;
    winrt::event_token BreakEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const;
    using BreakEnded_revoker = impl::event_revoker<Windows::Media::Playback::IMediaBreakManager, &impl::abi_t<Windows::Media::Playback::IMediaBreakManager>::remove_BreakEnded>;
    BreakEnded_revoker BreakEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const;
    void BreakEnded(winrt::event_token const& token) const noexcept;
    winrt::event_token BreakSkipped(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const;
    using BreakSkipped_revoker = impl::event_revoker<Windows::Media::Playback::IMediaBreakManager, &impl::abi_t<Windows::Media::Playback::IMediaBreakManager>::remove_BreakSkipped>;
    BreakSkipped_revoker BreakSkipped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const;
    void BreakSkipped(winrt::event_token const& token) const noexcept;
    Windows::Media::Playback::MediaBreak CurrentBreak() const;
    Windows::Media::Playback::MediaPlaybackSession PlaybackSession() const;
    void PlayBreak(Windows::Media::Playback::MediaBreak const& value) const;
    void SkipCurrentBreak() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakManager> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakManager<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakSchedule
{
    winrt::event_token ScheduleChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const& handler) const;
    using ScheduleChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaBreakSchedule, &impl::abi_t<Windows::Media::Playback::IMediaBreakSchedule>::remove_ScheduleChanged>;
    ScheduleChanged_revoker ScheduleChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const& handler) const;
    void ScheduleChanged(winrt::event_token const& token) const noexcept;
    void InsertMidrollBreak(Windows::Media::Playback::MediaBreak const& mediaBreak) const;
    void RemoveMidrollBreak(Windows::Media::Playback::MediaBreak const& mediaBreak) const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> MidrollBreaks() const;
    void PrerollBreak(Windows::Media::Playback::MediaBreak const& value) const;
    Windows::Media::Playback::MediaBreak PrerollBreak() const;
    void PostrollBreak(Windows::Media::Playback::MediaBreak const& value) const;
    Windows::Media::Playback::MediaBreak PostrollBreak() const;
    Windows::Media::Playback::MediaPlaybackItem PlaybackItem() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakSchedule> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakSchedule<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> SeekedOverBreaks() const;
    Windows::Foundation::TimeSpan OldPosition() const;
    Windows::Foundation::TimeSpan NewPosition() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakSkippedEventArgs
{
    Windows::Media::Playback::MediaBreak MediaBreak() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakSkippedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakSkippedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaBreakStartedEventArgs
{
    Windows::Media::Playback::MediaBreak MediaBreak() const;
};
template <> struct consume<Windows::Media::Playback::IMediaBreakStartedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaBreakStartedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaEnginePlaybackSource
{
    Windows::Media::Playback::MediaPlaybackItem CurrentItem() const;
    void SetPlaybackSource(Windows::Media::Playback::IMediaPlaybackSource const& source) const;
};
template <> struct consume<Windows::Media::Playback::IMediaEnginePlaybackSource> { template <typename D> using type = consume_Windows_Media_Playback_IMediaEnginePlaybackSource<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaItemDisplayProperties
{
    Windows::Media::MediaPlaybackType Type() const;
    void Type(Windows::Media::MediaPlaybackType const& value) const;
    Windows::Media::MusicDisplayProperties MusicProperties() const;
    Windows::Media::VideoDisplayProperties VideoProperties() const;
    Windows::Storage::Streams::RandomAccessStreamReference Thumbnail() const;
    void Thumbnail(Windows::Storage::Streams::RandomAccessStreamReference const& value) const;
    void ClearAll() const;
};
template <> struct consume<Windows::Media::Playback::IMediaItemDisplayProperties> { template <typename D> using type = consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManager
{
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::Media::Playback::MediaPlayer MediaPlayer() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior PlayBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior PauseBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior NextBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior PreviousBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior FastForwardBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior RewindBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior ShuffleBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior AutoRepeatModeBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior PositionBehavior() const;
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior RateBehavior() const;
    winrt::event_token PlayReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const;
    using PlayReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_PlayReceived>;
    PlayReceived_revoker PlayReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const;
    void PlayReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token PauseReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const;
    using PauseReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_PauseReceived>;
    PauseReceived_revoker PauseReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const;
    void PauseReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token NextReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const;
    using NextReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_NextReceived>;
    NextReceived_revoker NextReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const;
    void NextReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token PreviousReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const;
    using PreviousReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_PreviousReceived>;
    PreviousReceived_revoker PreviousReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const;
    void PreviousReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token FastForwardReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const;
    using FastForwardReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_FastForwardReceived>;
    FastForwardReceived_revoker FastForwardReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const;
    void FastForwardReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token RewindReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const;
    using RewindReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_RewindReceived>;
    RewindReceived_revoker RewindReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const;
    void RewindReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token ShuffleReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const;
    using ShuffleReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_ShuffleReceived>;
    ShuffleReceived_revoker ShuffleReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const;
    void ShuffleReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token AutoRepeatModeReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const;
    using AutoRepeatModeReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_AutoRepeatModeReceived>;
    AutoRepeatModeReceived_revoker AutoRepeatModeReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const;
    void AutoRepeatModeReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token PositionReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const;
    using PositionReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_PositionReceived>;
    PositionReceived_revoker PositionReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const;
    void PositionReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token RateReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const;
    using RateReceived_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManager, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManager>::remove_RateReceived>;
    RateReceived_revoker RateReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const;
    void RateReceived(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManager> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Media::MediaPlaybackAutoRepeatMode AutoRepeatMode() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior
{
    Windows::Media::Playback::MediaPlaybackCommandManager CommandManager() const;
    bool IsEnabled() const;
    Windows::Media::Playback::MediaCommandEnablingRule EnablingRule() const;
    void EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule const& value) const;
    winrt::event_token IsEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const& handler) const;
    using IsEnabledChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>::remove_IsEnabledChanged>;
    IsEnabledChanged_revoker IsEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const& handler) const;
    void IsEnabledChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::TimeSpan Position() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    double PlaybackRate() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    bool IsShuffleRequested() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItem
{
    winrt::event_token AudioTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    using AudioTracksChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackItem, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackItem>::remove_AudioTracksChanged>;
    AudioTracksChanged_revoker AudioTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    void AudioTracksChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token VideoTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    using VideoTracksChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackItem, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackItem>::remove_VideoTracksChanged>;
    VideoTracksChanged_revoker VideoTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    void VideoTracksChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token TimedMetadataTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    using TimedMetadataTracksChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackItem, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackItem>::remove_TimedMetadataTracksChanged>;
    TimedMetadataTracksChanged_revoker TimedMetadataTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const;
    void TimedMetadataTracksChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::Core::MediaSource Source() const;
    Windows::Media::Playback::MediaPlaybackAudioTrackList AudioTracks() const;
    Windows::Media::Playback::MediaPlaybackVideoTrackList VideoTracks() const;
    Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList TimedMetadataTracks() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItem> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItem<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItem2
{
    Windows::Media::Playback::MediaBreakSchedule BreakSchedule() const;
    Windows::Foundation::TimeSpan StartTime() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> DurationLimit() const;
    bool CanSkip() const;
    void CanSkip(bool value) const;
    Windows::Media::Playback::MediaItemDisplayProperties GetDisplayProperties() const;
    void ApplyDisplayProperties(Windows::Media::Playback::MediaItemDisplayProperties const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItem2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItem2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItem3
{
    bool IsDisabledInPlaybackList() const;
    void IsDisabledInPlaybackList(bool value) const;
    double TotalDownloadProgress() const;
    Windows::Media::Playback::AutoLoadedDisplayPropertyKind AutoLoadedDisplayProperties() const;
    void AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItem3> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItem3<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemError
{
    Windows::Media::Playback::MediaPlaybackItemErrorCode ErrorCode() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemError> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemError<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemFactory
{
    Windows::Media::Playback::MediaPlaybackItem Create(Windows::Media::Core::MediaSource const& source) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemFactory> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemFactory<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemFactory2
{
    Windows::Media::Playback::MediaPlaybackItem CreateWithStartTime(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime) const;
    Windows::Media::Playback::MediaPlaybackItem CreateWithStartTimeAndDurationLimit(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime, Windows::Foundation::TimeSpan const& durationLimit) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemFactory2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemFactory2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs
{
    Windows::Media::Playback::MediaPlaybackItem Item() const;
    Windows::Media::Playback::MediaPlaybackItemError Error() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemOpenedEventArgs
{
    Windows::Media::Playback::MediaPlaybackItem Item() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemOpenedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackItemStatics
{
    Windows::Media::Playback::MediaPlaybackItem FindFromMediaSource(Windows::Media::Core::MediaSource const& source) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackItemStatics> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackItemStatics<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackList
{
    winrt::event_token ItemFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const;
    using ItemFailed_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackList, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackList>::remove_ItemFailed>;
    ItemFailed_revoker ItemFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const;
    void ItemFailed(winrt::event_token const& token) const noexcept;
    winrt::event_token CurrentItemChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const;
    using CurrentItemChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackList, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackList>::remove_CurrentItemChanged>;
    CurrentItemChanged_revoker CurrentItemChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const;
    void CurrentItemChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token ItemOpened(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const;
    using ItemOpened_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackList, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackList>::remove_ItemOpened>;
    ItemOpened_revoker ItemOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const;
    void ItemOpened(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Collections::IObservableVector<Windows::Media::Playback::MediaPlaybackItem> Items() const;
    bool AutoRepeatEnabled() const;
    void AutoRepeatEnabled(bool value) const;
    bool ShuffleEnabled() const;
    void ShuffleEnabled(bool value) const;
    Windows::Media::Playback::MediaPlaybackItem CurrentItem() const;
    uint32_t CurrentItemIndex() const;
    Windows::Media::Playback::MediaPlaybackItem MoveNext() const;
    Windows::Media::Playback::MediaPlaybackItem MovePrevious() const;
    Windows::Media::Playback::MediaPlaybackItem MoveTo(uint32_t itemIndex) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackList> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackList<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackList2
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MaxPrefetchTime() const;
    void MaxPrefetchTime(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Media::Playback::MediaPlaybackItem StartingItem() const;
    void StartingItem(Windows::Media::Playback::MediaPlaybackItem const& value) const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaPlaybackItem> ShuffledItems() const;
    void SetShuffledItems(param::iterable<Windows::Media::Playback::MediaPlaybackItem> const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackList2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackList2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackList3
{
    Windows::Foundation::IReference<uint32_t> MaxPlayedItemsToKeepOpen() const;
    void MaxPlayedItemsToKeepOpen(optional<uint32_t> const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackList3> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackList3<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSession
{
    winrt::event_token PlaybackStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using PlaybackStateChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_PlaybackStateChanged>;
    PlaybackStateChanged_revoker PlaybackStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void PlaybackStateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PlaybackRateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using PlaybackRateChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_PlaybackRateChanged>;
    PlaybackRateChanged_revoker PlaybackRateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void PlaybackRateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SeekCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using SeekCompleted_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_SeekCompleted>;
    SeekCompleted_revoker SeekCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void SeekCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token BufferingStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using BufferingStarted_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_BufferingStarted>;
    BufferingStarted_revoker BufferingStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void BufferingStarted(winrt::event_token const& token) const noexcept;
    winrt::event_token BufferingEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using BufferingEnded_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_BufferingEnded>;
    BufferingEnded_revoker BufferingEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void BufferingEnded(winrt::event_token const& token) const noexcept;
    winrt::event_token BufferingProgressChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using BufferingProgressChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_BufferingProgressChanged>;
    BufferingProgressChanged_revoker BufferingProgressChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void BufferingProgressChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token DownloadProgressChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using DownloadProgressChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_DownloadProgressChanged>;
    DownloadProgressChanged_revoker DownloadProgressChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void DownloadProgressChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token NaturalDurationChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using NaturalDurationChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_NaturalDurationChanged>;
    NaturalDurationChanged_revoker NaturalDurationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void NaturalDurationChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using PositionChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_PositionChanged>;
    PositionChanged_revoker PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void PositionChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token NaturalVideoSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using NaturalVideoSizeChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession>::remove_NaturalVideoSizeChanged>;
    NaturalVideoSizeChanged_revoker NaturalVideoSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void NaturalVideoSizeChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::Playback::MediaPlayer MediaPlayer() const;
    Windows::Foundation::TimeSpan NaturalDuration() const;
    Windows::Foundation::TimeSpan Position() const;
    void Position(Windows::Foundation::TimeSpan const& value) const;
    Windows::Media::Playback::MediaPlaybackState PlaybackState() const;
    bool CanSeek() const;
    bool CanPause() const;
    bool IsProtected() const;
    double PlaybackRate() const;
    void PlaybackRate(double value) const;
    double BufferingProgress() const;
    double DownloadProgress() const;
    uint32_t NaturalVideoHeight() const;
    uint32_t NaturalVideoWidth() const;
    Windows::Foundation::Rect NormalizedSourceRect() const;
    void NormalizedSourceRect(Windows::Foundation::Rect const& value) const;
    Windows::Media::MediaProperties::StereoscopicVideoPackingMode StereoscopicVideoPackingMode() const;
    void StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSession> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSession<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSession2
{
    winrt::event_token BufferedRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using BufferedRangesChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession2, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession2>::remove_BufferedRangesChanged>;
    BufferedRangesChanged_revoker BufferedRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void BufferedRangesChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PlayedRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using PlayedRangesChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession2, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession2>::remove_PlayedRangesChanged>;
    PlayedRangesChanged_revoker PlayedRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void PlayedRangesChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SeekableRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using SeekableRangesChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession2, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession2>::remove_SeekableRangesChanged>;
    SeekableRangesChanged_revoker SeekableRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void SeekableRangesChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SupportedPlaybackRatesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    using SupportedPlaybackRatesChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackSession2, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackSession2>::remove_SupportedPlaybackRatesChanged>;
    SupportedPlaybackRatesChanged_revoker SupportedPlaybackRatesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const;
    void SupportedPlaybackRatesChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::Playback::MediaPlaybackSphericalVideoProjection SphericalVideoProjection() const;
    bool IsMirroring() const;
    void IsMirroring(bool value) const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> GetBufferedRanges() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> GetPlayedRanges() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> GetSeekableRanges() const;
    bool IsSupportedPlaybackRateRange(double rate1, double rate2) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSession2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSession2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSession3
{
    Windows::Media::MediaProperties::MediaRotation PlaybackRotation() const;
    void PlaybackRotation(Windows::Media::MediaProperties::MediaRotation const& value) const;
    Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState GetOutputDegradationPolicyState() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSession3> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSession3<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSessionBufferingStartedEventArgs
{
    bool IsPlaybackInterruption() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSessionBufferingStartedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSessionOutputDegradationPolicyState
{
    Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason VideoConstrictionReason() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSessionOutputDegradationPolicyState<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSource
{
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSource> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSource<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection
{
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::Media::MediaProperties::SphericalVideoFrameFormat FrameFormat() const;
    void FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const;
    double HorizontalFieldOfViewInDegrees() const;
    void HorizontalFieldOfViewInDegrees(double value) const;
    Windows::Foundation::Numerics::quaternion ViewOrientation() const;
    void ViewOrientation(Windows::Foundation::Numerics::quaternion const& value) const;
    Windows::Media::Playback::SphericalVideoProjectionMode ProjectionMode() const;
    void ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList
{
    winrt::event_token PresentationModeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const;
    using PresentationModeChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList, &impl::abi_t<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>::remove_PresentationModeChanged>;
    PresentationModeChanged_revoker PresentationModeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const;
    void PresentationModeChanged(winrt::event_token const& token) const noexcept;
    Windows::Media::Playback::TimedMetadataTrackPresentationMode GetPresentationMode(uint32_t index) const;
    void SetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer
{
    bool AutoPlay() const;
    void AutoPlay(bool value) const;
    Windows::Foundation::TimeSpan NaturalDuration() const;
    Windows::Foundation::TimeSpan Position() const;
    void Position(Windows::Foundation::TimeSpan const& value) const;
    double BufferingProgress() const;
    Windows::Media::Playback::MediaPlayerState CurrentState() const;
    bool CanSeek() const;
    bool CanPause() const;
    bool IsLoopingEnabled() const;
    void IsLoopingEnabled(bool value) const;
    bool IsProtected() const;
    bool IsMuted() const;
    void IsMuted(bool value) const;
    double PlaybackRate() const;
    void PlaybackRate(double value) const;
    double Volume() const;
    void Volume(double value) const;
    Windows::Media::Playback::PlaybackMediaMarkerSequence PlaybackMediaMarkers() const;
    winrt::event_token MediaOpened(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using MediaOpened_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_MediaOpened>;
    MediaOpened_revoker MediaOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void MediaOpened(winrt::event_token const& token) const noexcept;
    winrt::event_token MediaEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using MediaEnded_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_MediaEnded>;
    MediaEnded_revoker MediaEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void MediaEnded(winrt::event_token const& token) const noexcept;
    winrt::event_token MediaFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const;
    using MediaFailed_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_MediaFailed>;
    MediaFailed_revoker MediaFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const;
    void MediaFailed(winrt::event_token const& token) const noexcept;
    winrt::event_token CurrentStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using CurrentStateChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_CurrentStateChanged>;
    CurrentStateChanged_revoker CurrentStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void CurrentStateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PlaybackMediaMarkerReached(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const;
    using PlaybackMediaMarkerReached_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_PlaybackMediaMarkerReached>;
    PlaybackMediaMarkerReached_revoker PlaybackMediaMarkerReached(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const;
    void PlaybackMediaMarkerReached(winrt::event_token const& token) const noexcept;
    winrt::event_token MediaPlayerRateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const;
    using MediaPlayerRateChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_MediaPlayerRateChanged>;
    MediaPlayerRateChanged_revoker MediaPlayerRateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const;
    void MediaPlayerRateChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token VolumeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using VolumeChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_VolumeChanged>;
    VolumeChanged_revoker VolumeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void VolumeChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SeekCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using SeekCompleted_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_SeekCompleted>;
    SeekCompleted_revoker SeekCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void SeekCompleted(winrt::event_token const& token) const noexcept;
    winrt::event_token BufferingStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using BufferingStarted_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_BufferingStarted>;
    BufferingStarted_revoker BufferingStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void BufferingStarted(winrt::event_token const& token) const noexcept;
    winrt::event_token BufferingEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using BufferingEnded_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer, &impl::abi_t<Windows::Media::Playback::IMediaPlayer>::remove_BufferingEnded>;
    BufferingEnded_revoker BufferingEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void BufferingEnded(winrt::event_token const& token) const noexcept;
    void Play() const;
    void Pause() const;
    void SetUriSource(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer2
{
    Windows::Media::SystemMediaTransportControls SystemMediaTransportControls() const;
    Windows::Media::Playback::MediaPlayerAudioCategory AudioCategory() const;
    void AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory const& value) const;
    Windows::Media::Playback::MediaPlayerAudioDeviceType AudioDeviceType() const;
    void AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer3
{
    winrt::event_token IsMutedChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using IsMutedChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer3, &impl::abi_t<Windows::Media::Playback::IMediaPlayer3>::remove_IsMutedChanged>;
    IsMutedChanged_revoker IsMutedChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void IsMutedChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SourceChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using SourceChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer3, &impl::abi_t<Windows::Media::Playback::IMediaPlayer3>::remove_SourceChanged>;
    SourceChanged_revoker SourceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void SourceChanged(winrt::event_token const& token) const noexcept;
    double AudioBalance() const;
    void AudioBalance(double value) const;
    bool RealTimePlayback() const;
    void RealTimePlayback(bool value) const;
    Windows::Media::Playback::StereoscopicVideoRenderMode StereoscopicVideoRenderMode() const;
    void StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode const& value) const;
    Windows::Media::Playback::MediaBreakManager BreakManager() const;
    Windows::Media::Playback::MediaPlaybackCommandManager CommandManager() const;
    Windows::Devices::Enumeration::DeviceInformation AudioDevice() const;
    void AudioDevice(Windows::Devices::Enumeration::DeviceInformation const& value) const;
    Windows::Media::MediaTimelineController TimelineController() const;
    void TimelineController(Windows::Media::MediaTimelineController const& value) const;
    Windows::Foundation::TimeSpan TimelineControllerPositionOffset() const;
    void TimelineControllerPositionOffset(Windows::Foundation::TimeSpan const& value) const;
    Windows::Media::Playback::MediaPlaybackSession PlaybackSession() const;
    void StepForwardOneFrame() const;
    void StepBackwardOneFrame() const;
    Windows::Media::Casting::CastingSource GetAsCastingSource() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer3> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer3<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer4
{
    void SetSurfaceSize(Windows::Foundation::Size const& size) const;
    Windows::Media::Playback::MediaPlayerSurface GetSurface(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer4> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer4<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer5
{
    winrt::event_token VideoFrameAvailable(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    using VideoFrameAvailable_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer5, &impl::abi_t<Windows::Media::Playback::IMediaPlayer5>::remove_VideoFrameAvailable>;
    VideoFrameAvailable_revoker VideoFrameAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const;
    void VideoFrameAvailable(winrt::event_token const& token) const noexcept;
    bool IsVideoFrameServerEnabled() const;
    void IsVideoFrameServerEnabled(bool value) const;
    void CopyFrameToVideoSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const;
    void CopyFrameToVideoSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, Windows::Foundation::Rect const& targetRectangle) const;
    void CopyFrameToStereoscopicVideoSurfaces(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationLeftEye, Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationRightEye) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer5> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer5<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer6
{
    winrt::event_token SubtitleFrameChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& handler) const;
    using SubtitleFrameChanged_revoker = impl::event_revoker<Windows::Media::Playback::IMediaPlayer6, &impl::abi_t<Windows::Media::Playback::IMediaPlayer6>::remove_SubtitleFrameChanged>;
    SubtitleFrameChanged_revoker SubtitleFrameChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& handler) const;
    void SubtitleFrameChanged(winrt::event_token const& token) const noexcept;
    bool RenderSubtitlesToSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const;
    bool RenderSubtitlesToSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, Windows::Foundation::Rect const& targetRectangle) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer6> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer6<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayer7
{
    Windows::Media::Audio::AudioStateMonitor AudioStateMonitor() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayer7> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayer7<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerDataReceivedEventArgs
{
    Windows::Foundation::Collections::ValueSet Data() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerDataReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerEffects
{
    void AddAudioEffect(param::hstring const& activatableClassId, bool effectOptional, Windows::Foundation::Collections::IPropertySet const& configuration) const;
    void RemoveAllEffects() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerEffects> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerEffects<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerEffects2
{
    void AddVideoEffect(param::hstring const& activatableClassId, bool effectOptional, Windows::Foundation::Collections::IPropertySet const& effectConfiguration) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerEffects2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerEffects2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs
{
    Windows::Media::Playback::MediaPlayerError Error() const;
    winrt::hresult ExtendedErrorCode() const;
    hstring ErrorMessage() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerFailedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerRateChangedEventArgs
{
    double NewRate() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerRateChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerSource
{
    Windows::Media::Protection::MediaProtectionManager ProtectionManager() const;
    void ProtectionManager(Windows::Media::Protection::MediaProtectionManager const& value) const;
    void SetFileSource(Windows::Storage::IStorageFile const& file) const;
    void SetStreamSource(Windows::Storage::Streams::IRandomAccessStream const& stream) const;
    void SetMediaSource(Windows::Media::Core::IMediaSource const& source) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerSource> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerSource<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerSource2
{
    Windows::Media::Playback::IMediaPlaybackSource Source() const;
    void Source(Windows::Media::Playback::IMediaPlaybackSource const& value) const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerSource2> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerSource2<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IMediaPlayerSurface
{
    Windows::UI::Composition::ICompositionSurface CompositionSurface() const;
    Windows::UI::Composition::Compositor Compositor() const;
    Windows::Media::Playback::MediaPlayer MediaPlayer() const;
};
template <> struct consume<Windows::Media::Playback::IMediaPlayerSurface> { template <typename D> using type = consume_Windows_Media_Playback_IMediaPlayerSurface<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IPlaybackMediaMarker
{
    Windows::Foundation::TimeSpan Time() const;
    hstring MediaMarkerType() const;
    hstring Text() const;
};
template <> struct consume<Windows::Media::Playback::IPlaybackMediaMarker> { template <typename D> using type = consume_Windows_Media_Playback_IPlaybackMediaMarker<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory
{
    Windows::Media::Playback::PlaybackMediaMarker CreateFromTime(Windows::Foundation::TimeSpan const& value) const;
    Windows::Media::Playback::PlaybackMediaMarker Create(Windows::Foundation::TimeSpan const& value, param::hstring const& mediaMarketType, param::hstring const& text) const;
};
template <> struct consume<Windows::Media::Playback::IPlaybackMediaMarkerFactory> { template <typename D> using type = consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IPlaybackMediaMarkerReachedEventArgs
{
    Windows::Media::Playback::PlaybackMediaMarker PlaybackMediaMarker() const;
};
template <> struct consume<Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_IPlaybackMediaMarkerReachedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence
{
    uint32_t Size() const;
    void Insert(Windows::Media::Playback::PlaybackMediaMarker const& value) const;
    void Clear() const;
};
template <> struct consume<Windows::Media::Playback::IPlaybackMediaMarkerSequence> { template <typename D> using type = consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>; };

template <typename D>
struct consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs
{
    Windows::Media::Core::TimedMetadataTrack Track() const;
    Windows::Media::Playback::TimedMetadataTrackPresentationMode OldPresentationMode() const;
    Windows::Media::Playback::TimedMetadataTrackPresentationMode NewPresentationMode() const;
};
template <> struct consume<Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>; };

}
