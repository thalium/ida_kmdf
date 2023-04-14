// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media {

enum class MediaPlaybackAutoRepeatMode;
enum class MediaPlaybackType;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::Media::Control {

enum class GlobalSystemMediaTransportControlsSessionPlaybackStatus : int32_t
{
    Closed = 0,
    Opened = 1,
    Changing = 2,
    Stopped = 3,
    Playing = 4,
    Paused = 5,
};

struct ICurrentSessionChangedEventArgs;
struct IGlobalSystemMediaTransportControlsSession;
struct IGlobalSystemMediaTransportControlsSessionManager;
struct IGlobalSystemMediaTransportControlsSessionManagerStatics;
struct IGlobalSystemMediaTransportControlsSessionMediaProperties;
struct IGlobalSystemMediaTransportControlsSessionPlaybackControls;
struct IGlobalSystemMediaTransportControlsSessionPlaybackInfo;
struct IGlobalSystemMediaTransportControlsSessionTimelineProperties;
struct IMediaPropertiesChangedEventArgs;
struct IPlaybackInfoChangedEventArgs;
struct ISessionsChangedEventArgs;
struct ITimelinePropertiesChangedEventArgs;
struct CurrentSessionChangedEventArgs;
struct GlobalSystemMediaTransportControlsSession;
struct GlobalSystemMediaTransportControlsSessionManager;
struct GlobalSystemMediaTransportControlsSessionMediaProperties;
struct GlobalSystemMediaTransportControlsSessionPlaybackControls;
struct GlobalSystemMediaTransportControlsSessionPlaybackInfo;
struct GlobalSystemMediaTransportControlsSessionTimelineProperties;
struct MediaPropertiesChangedEventArgs;
struct PlaybackInfoChangedEventArgs;
struct SessionsChangedEventArgs;
struct TimelinePropertiesChangedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Control::ICurrentSessionChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IMediaPropertiesChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::IPlaybackInfoChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::ISessionsChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::ITimelinePropertiesChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Control::CurrentSessionChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties>{ using type = class_category; };
template <> struct category<Windows::Media::Control::MediaPropertiesChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Control::PlaybackInfoChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Control::SessionsChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Control::TimelinePropertiesChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus>{ using type = enum_category; };
template <> struct name<Windows::Media::Control::ICurrentSessionChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.ICurrentSessionChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSession" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManager" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionManagerStatics" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionMediaProperties" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackControls" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionPlaybackInfo" }; };
template <> struct name<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>{ static constexpr auto & value{ L"Windows.Media.Control.IGlobalSystemMediaTransportControlsSessionTimelineProperties" }; };
template <> struct name<Windows::Media::Control::IMediaPropertiesChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.IMediaPropertiesChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::IPlaybackInfoChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.IPlaybackInfoChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::ISessionsChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.ISessionsChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::ITimelinePropertiesChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.ITimelinePropertiesChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::CurrentSessionChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.CurrentSessionChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSession" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionManager" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionMediaProperties" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackControls" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackInfo" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionTimelineProperties" }; };
template <> struct name<Windows::Media::Control::MediaPropertiesChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.MediaPropertiesChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::PlaybackInfoChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.PlaybackInfoChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::SessionsChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.SessionsChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::TimelinePropertiesChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Control.TimelinePropertiesChangedEventArgs" }; };
template <> struct name<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus>{ static constexpr auto & value{ L"Windows.Media.Control.GlobalSystemMediaTransportControlsSessionPlaybackStatus" }; };
template <> struct guid_storage<Windows::Media::Control::ICurrentSessionChangedEventArgs>{ static constexpr guid value{ 0x6969CB39,0x0BFA,0x5FE0,{ 0x8D,0x73,0x09,0xCC,0x5E,0x54,0x08,0xE1 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>{ static constexpr guid value{ 0x7148C835,0x9B14,0x5AE2,{ 0xAB,0x85,0xDC,0x9B,0x1C,0x14,0xE1,0xA8 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>{ static constexpr guid value{ 0xCACE8EAC,0xE86E,0x504A,{ 0xAB,0x31,0x5F,0xF8,0xFF,0x1B,0xCE,0x49 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>{ static constexpr guid value{ 0x2050C4EE,0x11A0,0x57DE,{ 0xAE,0xD7,0xC9,0x7C,0x70,0x33,0x82,0x45 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>{ static constexpr guid value{ 0x68856CF6,0xADB4,0x54B2,{ 0xAC,0x16,0x05,0x83,0x79,0x07,0xAC,0xB6 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>{ static constexpr guid value{ 0x6501A3E6,0xBC7A,0x503A,{ 0xBB,0x1B,0x68,0xF1,0x58,0xF3,0xFB,0x03 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>{ static constexpr guid value{ 0x94B4B6CF,0xE8BA,0x51AD,{ 0x87,0xA7,0xC1,0x0A,0xDE,0x10,0x61,0x27 } }; };
template <> struct guid_storage<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>{ static constexpr guid value{ 0xEDE34136,0x6F25,0x588D,{ 0x8E,0xCF,0xEA,0x5B,0x67,0x35,0xAA,0xA5 } }; };
template <> struct guid_storage<Windows::Media::Control::IMediaPropertiesChangedEventArgs>{ static constexpr guid value{ 0x7D3741CB,0xADF0,0x5CEF,{ 0x91,0xBA,0xCF,0xAB,0xCD,0xD7,0x76,0x78 } }; };
template <> struct guid_storage<Windows::Media::Control::IPlaybackInfoChangedEventArgs>{ static constexpr guid value{ 0x786756C2,0xBC0D,0x50A5,{ 0x88,0x07,0x05,0x42,0x91,0xFE,0xF1,0x39 } }; };
template <> struct guid_storage<Windows::Media::Control::ISessionsChangedEventArgs>{ static constexpr guid value{ 0xBBF0CD32,0x42C4,0x5A58,{ 0xB3,0x17,0xF3,0x4B,0xBF,0xBD,0x26,0xE0 } }; };
template <> struct guid_storage<Windows::Media::Control::ITimelinePropertiesChangedEventArgs>{ static constexpr guid value{ 0x29033A2F,0xC923,0x5A77,{ 0xBC,0xAF,0x05,0x5F,0xF4,0x15,0xAD,0x32 } }; };
template <> struct default_interface<Windows::Media::Control::CurrentSessionChangedEventArgs>{ using type = Windows::Media::Control::ICurrentSessionChangedEventArgs; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSession; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo; };
template <> struct default_interface<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties>{ using type = Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties; };
template <> struct default_interface<Windows::Media::Control::MediaPropertiesChangedEventArgs>{ using type = Windows::Media::Control::IMediaPropertiesChangedEventArgs; };
template <> struct default_interface<Windows::Media::Control::PlaybackInfoChangedEventArgs>{ using type = Windows::Media::Control::IPlaybackInfoChangedEventArgs; };
template <> struct default_interface<Windows::Media::Control::SessionsChangedEventArgs>{ using type = Windows::Media::Control::ISessionsChangedEventArgs; };
template <> struct default_interface<Windows::Media::Control::TimelinePropertiesChangedEventArgs>{ using type = Windows::Media::Control::ITimelinePropertiesChangedEventArgs; };

template <> struct abi<Windows::Media::Control::ICurrentSessionChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SourceAppUserModelId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetMediaPropertiesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetTimelineProperties(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetPlaybackInfo(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryPlayAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryPauseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryStopAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryRecordAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryFastForwardAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryRewindAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySkipNextAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySkipPreviousAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangeChannelUpAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangeChannelDownAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryTogglePlayPauseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangeAutoRepeatModeAsync(Windows::Media::MediaPlaybackAutoRepeatMode requestedAutoRepeatMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangePlaybackRateAsync(double requestedPlaybackRate, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangeShuffleActiveAsync(bool requestedShuffleState, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_TimelinePropertiesChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TimelinePropertiesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PlaybackInfoChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PlaybackInfoChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_MediaPropertiesChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_MediaPropertiesChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetCurrentSession(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSessions(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_CurrentSessionChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CurrentSessionChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_SessionsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SessionsChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subtitle(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlbumArtist(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Artist(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlbumTitle(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrackNumber(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Genres(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlbumTrackCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPlayEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPauseEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStopEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRecordEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFastForwardEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRewindEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsNextEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPreviousEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsChannelUpEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsChannelDownEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPlayPauseToggleEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsShuffleEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRepeatEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPlaybackRateEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsPlaybackPositionEnabled(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Controls(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackStatus(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutoRepeatMode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PlaybackRate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsShuffleActive(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StartTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinSeekTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxSeekTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastUpdatedTime(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Control::IMediaPropertiesChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::Control::IPlaybackInfoChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::Control::ISessionsChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::Control::ITimelinePropertiesChangedEventArgs>{ struct type : IInspectable
{
};};

template <typename D>
struct consume_Windows_Media_Control_ICurrentSessionChangedEventArgs
{
};
template <> struct consume<Windows::Media::Control::ICurrentSessionChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Control_ICurrentSessionChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession
{
    hstring SourceAppUserModelId() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> TryGetMediaPropertiesAsync() const;
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties GetTimelineProperties() const;
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo GetPlaybackInfo() const;
    Windows::Foundation::IAsyncOperation<bool> TryPlayAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryPauseAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryStopAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryRecordAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryFastForwardAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryRewindAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TrySkipNextAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TrySkipPreviousAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryChangeChannelUpAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryChangeChannelDownAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryTogglePlayPauseAsync() const;
    Windows::Foundation::IAsyncOperation<bool> TryChangeAutoRepeatModeAsync(Windows::Media::MediaPlaybackAutoRepeatMode const& requestedAutoRepeatMode) const;
    Windows::Foundation::IAsyncOperation<bool> TryChangePlaybackRateAsync(double requestedPlaybackRate) const;
    Windows::Foundation::IAsyncOperation<bool> TryChangeShuffleActiveAsync(bool requestedShuffleState) const;
    Windows::Foundation::IAsyncOperation<bool> TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition) const;
    winrt::event_token TimelinePropertiesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const;
    using TimelinePropertiesChanged_revoker = impl::event_revoker<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession, &impl::abi_t<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>::remove_TimelinePropertiesChanged>;
    TimelinePropertiesChanged_revoker TimelinePropertiesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const;
    void TimelinePropertiesChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token PlaybackInfoChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const;
    using PlaybackInfoChanged_revoker = impl::event_revoker<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession, &impl::abi_t<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>::remove_PlaybackInfoChanged>;
    PlaybackInfoChanged_revoker PlaybackInfoChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const;
    void PlaybackInfoChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token MediaPropertiesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const;
    using MediaPropertiesChanged_revoker = impl::event_revoker<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession, &impl::abi_t<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>::remove_MediaPropertiesChanged>;
    MediaPropertiesChanged_revoker MediaPropertiesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const;
    void MediaPropertiesChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSession GetCurrentSession() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Control::GlobalSystemMediaTransportControlsSession> GetSessions() const;
    winrt::event_token CurrentSessionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const;
    using CurrentSessionChanged_revoker = impl::event_revoker<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager, &impl::abi_t<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>::remove_CurrentSessionChanged>;
    CurrentSessionChanged_revoker CurrentSessionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const;
    void CurrentSessionChanged(winrt::event_token const& token) const noexcept;
    winrt::event_token SessionsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const& handler) const;
    using SessionsChanged_revoker = impl::event_revoker<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager, &impl::abi_t<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>::remove_SessionsChanged>;
    SessionsChanged_revoker SessionsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const& handler) const;
    void SessionsChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> RequestAsync() const;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties
{
    hstring Title() const;
    hstring Subtitle() const;
    hstring AlbumArtist() const;
    hstring Artist() const;
    hstring AlbumTitle() const;
    int32_t TrackNumber() const;
    Windows::Foundation::Collections::IVectorView<hstring> Genres() const;
    int32_t AlbumTrackCount() const;
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> PlaybackType() const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls
{
    bool IsPlayEnabled() const;
    bool IsPauseEnabled() const;
    bool IsStopEnabled() const;
    bool IsRecordEnabled() const;
    bool IsFastForwardEnabled() const;
    bool IsRewindEnabled() const;
    bool IsNextEnabled() const;
    bool IsPreviousEnabled() const;
    bool IsChannelUpEnabled() const;
    bool IsChannelDownEnabled() const;
    bool IsPlayPauseToggleEnabled() const;
    bool IsShuffleEnabled() const;
    bool IsRepeatEnabled() const;
    bool IsPlaybackRateEnabled() const;
    bool IsPlaybackPositionEnabled() const;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls Controls() const;
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus PlaybackStatus() const;
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> PlaybackType() const;
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackAutoRepeatMode> AutoRepeatMode() const;
    Windows::Foundation::IReference<double> PlaybackRate() const;
    Windows::Foundation::IReference<bool> IsShuffleActive() const;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>; };

template <typename D>
struct consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties
{
    Windows::Foundation::TimeSpan StartTime() const;
    Windows::Foundation::TimeSpan EndTime() const;
    Windows::Foundation::TimeSpan MinSeekTime() const;
    Windows::Foundation::TimeSpan MaxSeekTime() const;
    Windows::Foundation::TimeSpan Position() const;
    Windows::Foundation::DateTime LastUpdatedTime() const;
};
template <> struct consume<Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> { template <typename D> using type = consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>; };

template <typename D>
struct consume_Windows_Media_Control_IMediaPropertiesChangedEventArgs
{
};
template <> struct consume<Windows::Media::Control::IMediaPropertiesChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Control_IMediaPropertiesChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Control_IPlaybackInfoChangedEventArgs
{
};
template <> struct consume<Windows::Media::Control::IPlaybackInfoChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Control_IPlaybackInfoChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Control_ISessionsChangedEventArgs
{
};
template <> struct consume<Windows::Media::Control::ISessionsChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Control_ISessionsChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Control_ITimelinePropertiesChangedEventArgs
{
};
template <> struct consume<Windows::Media::Control::ITimelinePropertiesChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Control_ITimelinePropertiesChangedEventArgs<D>; };

}
