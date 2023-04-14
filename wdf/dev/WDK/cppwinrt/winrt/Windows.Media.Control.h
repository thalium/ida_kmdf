// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.Control.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::SourceAppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->get_SourceAppUserModelId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryGetMediaPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryGetMediaPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::GetTimelineProperties() const
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->GetTimelineProperties(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::GetPlaybackInfo() const
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->GetPlaybackInfo(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryPlayAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryPlayAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryPauseAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryPauseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryStopAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryStopAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryRecordAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryRecordAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryFastForwardAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryFastForwardAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryRewindAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryRewindAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TrySkipNextAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TrySkipNextAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TrySkipPreviousAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TrySkipPreviousAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeChannelUpAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeChannelUpAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeChannelDownAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeChannelDownAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryTogglePlayPauseAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryTogglePlayPauseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeAutoRepeatModeAsync(Windows::Media::MediaPlaybackAutoRepeatMode const& requestedAutoRepeatMode) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeAutoRepeatModeAsync(get_abi(requestedAutoRepeatMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangePlaybackRateAsync(double requestedPlaybackRate) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangePlaybackRateAsync(requestedPlaybackRate, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangeShuffleActiveAsync(bool requestedShuffleState) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangeShuffleActiveAsync(requestedShuffleState, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->TryChangePlaybackPositionAsync(requestedPlaybackPosition, put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_TimelinePropertiesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TimelinePropertiesChanged_revoker>(this, TimelinePropertiesChanged(handler));
}

template <typename D> void consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::TimelinePropertiesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_TimelinePropertiesChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_PlaybackInfoChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlaybackInfoChanged_revoker>(this, PlaybackInfoChanged(handler));
}

template <typename D> void consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::PlaybackInfoChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_PlaybackInfoChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->add_MediaPropertiesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MediaPropertiesChanged_revoker>(this, MediaPropertiesChanged(handler));
}

template <typename D> void consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSession<D>::MediaPropertiesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSession)->remove_MediaPropertiesChanged(get_abi(token)));
}

template <typename D> Windows::Media::Control::GlobalSystemMediaTransportControlsSession consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::GetCurrentSession() const
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->GetCurrentSession(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Control::GlobalSystemMediaTransportControlsSession> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::GetSessions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Control::GlobalSystemMediaTransportControlsSession> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->GetSessions(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->add_CurrentSessionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CurrentSessionChanged_revoker>(this, CurrentSessionChanged(handler));
}

template <typename D> void consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::CurrentSessionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->remove_CurrentSessionChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->add_SessionsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged_revoker consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SessionsChanged_revoker>(this, SessionsChanged(handler));
}

template <typename D> void consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManager<D>::SessionsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager)->remove_SessionsChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionManagerStatics<D>::RequestAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics)->RequestAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumArtist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumArtist(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Artist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Artist(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumTitle(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::TrackNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_TrackNumber(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Genres() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Genres(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::AlbumTrackCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_AlbumTrackCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::PlaybackType() const
{
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_PlaybackType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionMediaProperties<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlayEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlayEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPauseEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPauseEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsStopEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsStopEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRecordEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRecordEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsFastForwardEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsFastForwardEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRewindEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRewindEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsNextEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsNextEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPreviousEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPreviousEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsChannelUpEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsChannelUpEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsChannelDownEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsChannelDownEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlayPauseToggleEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlayPauseToggleEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsShuffleEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsShuffleEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsRepeatEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsRepeatEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlaybackRateEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlaybackRateEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackControls<D>::IsPlaybackPositionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls)->get_IsPlaybackPositionEnabled(&value));
    return value;
}

template <typename D> Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::Controls() const
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_Controls(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackStatus() const
{
    Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackType() const
{
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::MediaPlaybackAutoRepeatMode> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::AutoRepeatMode() const
{
    Windows::Foundation::IReference<Windows::Media::MediaPlaybackAutoRepeatMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_AutoRepeatMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::PlaybackRate() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_PlaybackRate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionPlaybackInfo<D>::IsShuffleActive() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo)->get_IsShuffleActive(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::StartTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::EndTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_EndTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::MinSeekTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_MinSeekTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::MaxSeekTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_MaxSeekTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Control_IGlobalSystemMediaTransportControlsSessionTimelineProperties<D>::LastUpdatedTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties)->get_LastUpdatedTime(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Control::ICurrentSessionChangedEventArgs> : produce_base<D, Windows::Media::Control::ICurrentSessionChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSession>
{
    int32_t WINRT_CALL get_SourceAppUserModelId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceAppUserModelId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceAppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetMediaPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetMediaPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties>>(this->shim().TryGetMediaPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTimelineProperties(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimelineProperties, WINRT_WRAP(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties));
            *result = detach_from<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties>(this->shim().GetTimelineProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPlaybackInfo(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPlaybackInfo, WINRT_WRAP(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo));
            *result = detach_from<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo>(this->shim().GetPlaybackInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPlayAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPlayAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPlayAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPauseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPauseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStopAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStopAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryStopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRecordAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRecordAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryFastForwardAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryFastForwardAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryFastForwardAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRewindAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRewindAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRewindAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySkipNextAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySkipNextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySkipNextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySkipPreviousAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySkipPreviousAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySkipPreviousAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangeChannelUpAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangeChannelUpAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeChannelUpAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangeChannelDownAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangeChannelDownAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeChannelDownAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTogglePlayPauseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTogglePlayPauseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryTogglePlayPauseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangeAutoRepeatModeAsync(Windows::Media::MediaPlaybackAutoRepeatMode requestedAutoRepeatMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangeAutoRepeatModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Media::MediaPlaybackAutoRepeatMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeAutoRepeatModeAsync(*reinterpret_cast<Windows::Media::MediaPlaybackAutoRepeatMode const*>(&requestedAutoRepeatMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangePlaybackRateAsync(double requestedPlaybackRate, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangePlaybackRateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangePlaybackRateAsync(requestedPlaybackRate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangeShuffleActiveAsync(bool requestedShuffleState, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangeShuffleActiveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), bool);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangeShuffleActiveAsync(requestedShuffleState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryChangePlaybackPositionAsync(int64_t requestedPlaybackPosition, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryChangePlaybackPositionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int64_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryChangePlaybackPositionAsync(requestedPlaybackPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TimelinePropertiesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimelinePropertiesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TimelinePropertiesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::TimelinePropertiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TimelinePropertiesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TimelinePropertiesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TimelinePropertiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackInfoChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackInfoChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackInfoChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::PlaybackInfoChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackInfoChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackInfoChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackInfoChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MediaPropertiesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPropertiesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaPropertiesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSession, Windows::Media::Control::MediaPropertiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaPropertiesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaPropertiesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaPropertiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager>
{
    int32_t WINRT_CALL GetCurrentSession(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSession, WINRT_WRAP(Windows::Media::Control::GlobalSystemMediaTransportControlsSession));
            *result = detach_from<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>(this->shim().GetCurrentSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSessions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSessions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Control::GlobalSystemMediaTransportControlsSession>>(this->shim().GetSessions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CurrentSessionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentSessionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentSessionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::CurrentSessionChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentSessionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentSessionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentSessionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SessionsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SessionsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::SessionsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SessionsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SessionsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SessionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>
{
    int32_t WINRT_CALL RequestAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager>>(this->shim().RequestAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumArtist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArtist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Artist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Artist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Artist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Genres(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Genres, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Genres());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumTrackCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTrackCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AlbumTrackCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackType, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::MediaPlaybackType>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::MediaPlaybackType>>(this->shim().PlaybackType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls>
{
    int32_t WINRT_CALL get_IsPlayEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlayEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPauseEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPauseEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPauseEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStopEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStopEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStopEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRecordEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRecordEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRecordEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFastForwardEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFastForwardEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFastForwardEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRewindEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRewindEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRewindEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNextEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNextEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNextEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPreviousEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPreviousEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPreviousEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChannelUpEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelUpEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsChannelUpEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChannelDownEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelDownEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsChannelDownEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlayPauseToggleEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayPauseToggleEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlayPauseToggleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsShuffleEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShuffleEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRepeatEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRepeatEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRepeatEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlaybackRateEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaybackRateEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlaybackRateEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlaybackPositionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaybackPositionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlaybackPositionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo>
{
    int32_t WINRT_CALL get_Controls(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controls, WINRT_WRAP(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls));
            *value = detach_from<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls>(this->shim().Controls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackStatus(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackStatus, WINRT_WRAP(Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus));
            *value = detach_from<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackStatus>(this->shim().PlaybackStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackType, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::MediaPlaybackType>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::MediaPlaybackType>>(this->shim().PlaybackType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRepeatMode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatMode, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::MediaPlaybackAutoRepeatMode>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::MediaPlaybackAutoRepeatMode>>(this->shim().AutoRepeatMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsShuffleActive(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShuffleActive, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsShuffleActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> : produce_base<D, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties>
{
    int32_t WINRT_CALL get_StartTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSeekTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSeekTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MinSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSeekTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSeekTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaxSeekTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastUpdatedTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastUpdatedTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastUpdatedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Control::IMediaPropertiesChangedEventArgs> : produce_base<D, Windows::Media::Control::IMediaPropertiesChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Control::IPlaybackInfoChangedEventArgs> : produce_base<D, Windows::Media::Control::IPlaybackInfoChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Control::ISessionsChangedEventArgs> : produce_base<D, Windows::Media::Control::ISessionsChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Control::ITimelinePropertiesChangedEventArgs> : produce_base<D, Windows::Media::Control::ITimelinePropertiesChangedEventArgs>
{};

}

WINRT_EXPORT namespace winrt::Windows::Media::Control {

inline Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> GlobalSystemMediaTransportControlsSessionManager::RequestAsync()
{
    return impl::call_factory<GlobalSystemMediaTransportControlsSessionManager, Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics>([&](auto&& f) { return f.RequestAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Control::ICurrentSessionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::ICurrentSessionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSession> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo> {};
template<> struct hash<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> : winrt::impl::hash_base<winrt::Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties> {};
template<> struct hash<winrt::Windows::Media::Control::IMediaPropertiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::IMediaPropertiesChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::IPlaybackInfoChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::IPlaybackInfoChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::ISessionsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::ISessionsChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::ITimelinePropertiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::ITimelinePropertiesChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::CurrentSessionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSession> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionMediaProperties> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackControls> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionPlaybackInfo> {};
template<> struct hash<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties> : winrt::impl::hash_base<winrt::Windows::Media::Control::GlobalSystemMediaTransportControlsSessionTimelineProperties> {};
template<> struct hash<winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::MediaPropertiesChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::PlaybackInfoChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::SessionsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::SessionsChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Control::TimelinePropertiesChangedEventArgs> {};

}
