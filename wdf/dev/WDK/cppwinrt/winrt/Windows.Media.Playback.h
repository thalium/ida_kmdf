// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Audio.2.h"
#include "winrt/impl/Windows.Media.Casting.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Playback::MediaPlayer consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::Current() const
{
    Windows::Media::Playback::MediaPlayer player{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->get_Current(put_abi(player)));
    return player;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->add_MessageReceivedFromBackground(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground_revoker consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MessageReceivedFromBackground_revoker>(this, MessageReceivedFromBackground(value));
}

template <typename D> void consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->remove_MessageReceivedFromBackground(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->add_MessageReceivedFromForeground(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground_revoker consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MessageReceivedFromForeground_revoker>(this, MessageReceivedFromForeground(value));
}

template <typename D> void consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::MessageReceivedFromForeground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->remove_MessageReceivedFromForeground(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::SendMessageToBackground(Windows::Foundation::Collections::ValueSet const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->SendMessageToBackground(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::SendMessageToForeground(Windows::Foundation::Collections::ValueSet const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->SendMessageToForeground(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::IsMediaPlaying() const
{
    bool isMediaPlaying{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->IsMediaPlaying(&isMediaPlaying));
    return isMediaPlaying;
}

template <typename D> void consume_Windows_Media_Playback_IBackgroundMediaPlayerStatics<D>::Shutdown() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IBackgroundMediaPlayerStatics)->Shutdown());
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs<D>::NewItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs)->get_NewItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs<D>::OldItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs)->get_OldItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItemChangedReason consume_Windows_Media_Playback_ICurrentMediaPlaybackItemChangedEventArgs2<D>::Reason() const
{
    Windows::Media::Playback::MediaPlaybackItemChangedReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackList consume_Windows_Media_Playback_IMediaBreak<D>::PlaybackList() const
{
    Windows::Media::Playback::MediaPlaybackList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->get_PlaybackList(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Playback_IMediaBreak<D>::PresentationPosition() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->get_PresentationPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaBreakInsertionMethod consume_Windows_Media_Playback_IMediaBreak<D>::InsertionMethod() const
{
    Windows::Media::Playback::MediaBreakInsertionMethod value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->get_InsertionMethod(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Media_Playback_IMediaBreak<D>::CustomProperties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->get_CustomProperties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaBreak<D>::CanStart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->get_CanStart(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreak<D>::CanStart(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreak)->put_CanStart(value));
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakEndedEventArgs<D>::MediaBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakEndedEventArgs)->get_MediaBreak(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakFactory<D>::Create(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod) const
{
    Windows::Media::Playback::MediaBreak result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakFactory)->Create(get_abi(insertionMethod), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakFactory<D>::CreateWithPresentationPosition(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod, Windows::Foundation::TimeSpan const& presentationPosition) const
{
    Windows::Media::Playback::MediaBreak result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakFactory)->CreateWithPresentationPosition(get_abi(insertionMethod), get_abi(presentationPosition), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->add_BreaksSeekedOver(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BreaksSeekedOver_revoker>(this, BreaksSeekedOver(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::BreaksSeekedOver(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->remove_BreaksSeekedOver(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->add_BreakStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BreakStarted_revoker>(this, BreakStarted(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->remove_BreakStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->add_BreakEnded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BreakEnded_revoker>(this, BreakEnded(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->remove_BreakEnded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->add_BreakSkipped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped_revoker consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BreakSkipped_revoker>(this, BreakSkipped(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::BreakSkipped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->remove_BreakSkipped(get_abi(token)));
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakManager<D>::CurrentBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->get_CurrentBreak(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackSession consume_Windows_Media_Playback_IMediaBreakManager<D>::PlaybackSession() const
{
    Windows::Media::Playback::MediaPlaybackSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->get_PlaybackSession(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::PlayBreak(Windows::Media::Playback::MediaBreak const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->PlayBreak(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakManager<D>::SkipCurrentBreak() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakManager)->SkipCurrentBreak());
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->add_ScheduleChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged_revoker consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ScheduleChanged_revoker>(this, ScheduleChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakSchedule<D>::ScheduleChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->remove_ScheduleChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakSchedule<D>::InsertMidrollBreak(Windows::Media::Playback::MediaBreak const& mediaBreak) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->InsertMidrollBreak(get_abi(mediaBreak)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakSchedule<D>::RemoveMidrollBreak(Windows::Media::Playback::MediaBreak const& mediaBreak) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->RemoveMidrollBreak(get_abi(mediaBreak)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> consume_Windows_Media_Playback_IMediaBreakSchedule<D>::MidrollBreaks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->get_MidrollBreaks(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PrerollBreak(Windows::Media::Playback::MediaBreak const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->put_PrerollBreak(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PrerollBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->get_PrerollBreak(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PostrollBreak(Windows::Media::Playback::MediaBreak const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->put_PostrollBreak(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PostrollBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->get_PostrollBreak(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaBreakSchedule<D>::PlaybackItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSchedule)->get_PlaybackItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::SeekedOverBreaks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_SeekedOverBreaks(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::OldPosition() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_OldPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaBreakSeekedOverEventArgs<D>::NewPosition() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSeekedOverEventArgs)->get_NewPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakSkippedEventArgs<D>::MediaBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakSkippedEventArgs)->get_MediaBreak(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaBreak consume_Windows_Media_Playback_IMediaBreakStartedEventArgs<D>::MediaBreak() const
{
    Windows::Media::Playback::MediaBreak value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaBreakStartedEventArgs)->get_MediaBreak(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaEnginePlaybackSource<D>::CurrentItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaEnginePlaybackSource)->get_CurrentItem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaEnginePlaybackSource<D>::SetPlaybackSource(Windows::Media::Playback::IMediaPlaybackSource const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaEnginePlaybackSource)->SetPlaybackSource(get_abi(source)));
}

template <typename D> Windows::Media::MediaPlaybackType consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Type() const
{
    Windows::Media::MediaPlaybackType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Type(Windows::Media::MediaPlaybackType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->put_Type(get_abi(value)));
}

template <typename D> Windows::Media::MusicDisplayProperties consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::MusicProperties() const
{
    Windows::Media::MusicDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->get_MusicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoDisplayProperties consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::VideoProperties() const
{
    Windows::Media::VideoDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->get_VideoProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::RandomAccessStreamReference consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Thumbnail() const
{
    Windows::Storage::Streams::RandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::Thumbnail(Windows::Storage::Streams::RandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->put_Thumbnail(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaItemDisplayProperties<D>::ClearAll() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaItemDisplayProperties)->ClearAll());
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->put_IsEnabled(value));
}

template <typename D> Windows::Media::Playback::MediaPlayer consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::MediaPlayer() const
{
    Windows::Media::Playback::MediaPlayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_MediaPlayer(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PlayBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PauseBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_NextBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PreviousBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_FastForwardBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_RewindBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_ShuffleBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_AutoRepeatModeBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_PositionBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateBehavior() const
{
    Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->get_RateBehavior(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PlayReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlayReceived_revoker>(this, PlayReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PlayReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PlayReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PauseReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PauseReceived_revoker>(this, PauseReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PauseReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PauseReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_NextReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NextReceived_revoker>(this, NextReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::NextReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_NextReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PreviousReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PreviousReceived_revoker>(this, PreviousReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PreviousReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PreviousReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_FastForwardReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FastForwardReceived_revoker>(this, FastForwardReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::FastForwardReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_FastForwardReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_RewindReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RewindReceived_revoker>(this, RewindReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RewindReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_RewindReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_ShuffleReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ShuffleReceived_revoker>(this, ShuffleReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::ShuffleReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_ShuffleReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_AutoRepeatModeReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AutoRepeatModeReceived_revoker>(this, AutoRepeatModeReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::AutoRepeatModeReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_AutoRepeatModeReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_PositionReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PositionReceived_revoker>(this, PositionReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::PositionReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_PositionReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->add_RateReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RateReceived_revoker>(this, RateReceived(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManager<D>::RateReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManager)->remove_RateReceived(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Media::MediaPlaybackAutoRepeatMode consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::AutoRepeatMode() const
{
    Windows::Media::MediaPlaybackAutoRepeatMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->get_AutoRepeatMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManager consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::CommandManager() const
{
    Windows::Media::Playback::MediaPlaybackCommandManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_CommandManager(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_IsEnabled(&value));
    return value;
}

template <typename D> Windows::Media::Playback::MediaCommandEnablingRule consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::EnablingRule() const
{
    Windows::Media::Playback::MediaCommandEnablingRule value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->get_EnablingRule(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->put_EnablingRule(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->add_IsEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsEnabledChanged_revoker>(this, IsEnabledChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerCommandBehavior<D>::IsEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior)->remove_IsEnabledChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerFastForwardReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerNextReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPauseReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPlayReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPositionReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerPreviousReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->put_Handled(value));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::PlaybackRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->get_PlaybackRate(&value));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRateReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerRewindReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->put_Handled(value));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::IsShuffleRequested() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->get_IsShuffleRequested(&value));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Playback_IMediaPlaybackCommandManagerShuffleReceivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->add_AudioTracksChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AudioTracksChanged_revoker>(this, AudioTracksChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracksChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->remove_AudioTracksChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->add_VideoTracksChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VideoTracksChanged_revoker>(this, VideoTracksChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracksChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->remove_VideoTracksChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->add_TimedMetadataTracksChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TimedMetadataTracksChanged_revoker>(this, TimedMetadataTracksChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracksChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->remove_TimedMetadataTracksChanged(get_abi(token)));
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Playback_IMediaPlaybackItem<D>::Source() const
{
    Windows::Media::Core::MediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackAudioTrackList consume_Windows_Media_Playback_IMediaPlaybackItem<D>::AudioTracks() const
{
    Windows::Media::Playback::MediaPlaybackAudioTrackList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->get_AudioTracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackVideoTrackList consume_Windows_Media_Playback_IMediaPlaybackItem<D>::VideoTracks() const
{
    Windows::Media::Playback::MediaPlaybackVideoTrackList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->get_VideoTracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList consume_Windows_Media_Playback_IMediaPlaybackItem<D>::TimedMetadataTracks() const
{
    Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem)->get_TimedMetadataTracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaBreakSchedule consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::BreakSchedule() const
{
    Windows::Media::Playback::MediaBreakSchedule value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->get_BreakSchedule(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::StartTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::DurationLimit() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->get_DurationLimit(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::CanSkip() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->get_CanSkip(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::CanSkip(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->put_CanSkip(value));
}

template <typename D> Windows::Media::Playback::MediaItemDisplayProperties consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::GetDisplayProperties() const
{
    Windows::Media::Playback::MediaItemDisplayProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->GetDisplayProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem2<D>::ApplyDisplayProperties(Windows::Media::Playback::MediaItemDisplayProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem2)->ApplyDisplayProperties(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::IsDisabledInPlaybackList() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem3)->get_IsDisabledInPlaybackList(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::IsDisabledInPlaybackList(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem3)->put_IsDisabledInPlaybackList(value));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::TotalDownloadProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem3)->get_TotalDownloadProgress(&value));
    return value;
}

template <typename D> Windows::Media::Playback::AutoLoadedDisplayPropertyKind consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::AutoLoadedDisplayProperties() const
{
    Windows::Media::Playback::AutoLoadedDisplayPropertyKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem3)->get_AutoLoadedDisplayProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackItem3<D>::AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItem3)->put_AutoLoadedDisplayProperties(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackItemErrorCode consume_Windows_Media_Playback_IMediaPlaybackItemError<D>::ErrorCode() const
{
    Windows::Media::Playback::MediaPlaybackItemErrorCode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemError)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Playback_IMediaPlaybackItemError<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemError)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemFactory<D>::Create(Windows::Media::Core::MediaSource const& source) const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemFactory)->Create(get_abi(source), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemFactory2<D>::CreateWithStartTime(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime) const
{
    Windows::Media::Playback::MediaPlaybackItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemFactory2)->CreateWithStartTime(get_abi(source), get_abi(startTime), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemFactory2<D>::CreateWithStartTimeAndDurationLimit(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime, Windows::Foundation::TimeSpan const& durationLimit) const
{
    Windows::Media::Playback::MediaPlaybackItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemFactory2)->CreateWithStartTimeAndDurationLimit(get_abi(source), get_abi(startTime), get_abi(durationLimit), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs<D>::Item() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs)->get_Item(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItemError consume_Windows_Media_Playback_IMediaPlaybackItemFailedEventArgs<D>::Error() const
{
    Windows::Media::Playback::MediaPlaybackItemError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemOpenedEventArgs<D>::Item() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs)->get_Item(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackItemStatics<D>::FindFromMediaSource(Windows::Media::Core::MediaSource const& source) const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackItemStatics)->FindFromMediaSource(get_abi(source), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->add_ItemFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemFailed_revoker>(this, ItemFailed(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->remove_ItemFailed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->add_CurrentItemChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CurrentItemChanged_revoker>(this, CurrentItemChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->remove_CurrentItemChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->add_ItemOpened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened_revoker consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemOpened_revoker>(this, ItemOpened(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList<D>::ItemOpened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->remove_ItemOpened(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Media::Playback::MediaPlaybackItem> consume_Windows_Media_Playback_IMediaPlaybackList<D>::Items() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Media::Playback::MediaPlaybackItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->get_Items(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackList<D>::AutoRepeatEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->get_AutoRepeatEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList<D>::AutoRepeatEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->put_AutoRepeatEnabled(value));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackList<D>::ShuffleEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->get_ShuffleEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList<D>::ShuffleEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->put_ShuffleEnabled(value));
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->get_CurrentItem(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Playback_IMediaPlaybackList<D>::CurrentItemIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->get_CurrentItemIndex(&value));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackList<D>::MoveNext() const
{
    Windows::Media::Playback::MediaPlaybackItem item{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->MoveNext(put_abi(item)));
    return item;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackList<D>::MovePrevious() const
{
    Windows::Media::Playback::MediaPlaybackItem item{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->MovePrevious(put_abi(item)));
    return item;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackList<D>::MoveTo(uint32_t itemIndex) const
{
    Windows::Media::Playback::MediaPlaybackItem item{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList)->MoveTo(itemIndex, put_abi(item)));
    return item;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Playback_IMediaPlaybackList2<D>::MaxPrefetchTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->get_MaxPrefetchTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList2<D>::MaxPrefetchTime(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->put_MaxPrefetchTime(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Playback_IMediaPlaybackList2<D>::StartingItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->get_StartingItem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList2<D>::StartingItem(Windows::Media::Playback::MediaPlaybackItem const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->put_StartingItem(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaPlaybackItem> consume_Windows_Media_Playback_IMediaPlaybackList2<D>::ShuffledItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaPlaybackItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->get_ShuffledItems(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList2<D>::SetShuffledItems(param::iterable<Windows::Media::Playback::MediaPlaybackItem> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList2)->SetShuffledItems(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Playback_IMediaPlaybackList3<D>::MaxPlayedItemsToKeepOpen() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList3)->get_MaxPlayedItemsToKeepOpen(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackList3<D>::MaxPlayedItemsToKeepOpen(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackList3)->put_MaxPlayedItemsToKeepOpen(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_PlaybackStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, PlaybackStateChanged_revoker>(this, PlaybackStateChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_PlaybackStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_PlaybackRateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, PlaybackRateChanged_revoker>(this, PlaybackRateChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_PlaybackRateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_SeekCompleted(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, SeekCompleted_revoker>(this, SeekCompleted(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::SeekCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_SeekCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingStarted(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferingStarted_revoker>(this, BufferingStarted(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingEnded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferingEnded_revoker>(this, BufferingEnded(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingEnded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_BufferingProgressChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferingProgressChanged_revoker>(this, BufferingProgressChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgressChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_BufferingProgressChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_DownloadProgressChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, DownloadProgressChanged_revoker>(this, DownloadProgressChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgressChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_DownloadProgressChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_NaturalDurationChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, NaturalDurationChanged_revoker>(this, NaturalDurationChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDurationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_NaturalDurationChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_PositionChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PositionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_PositionChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->add_NaturalVideoSizeChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, NaturalVideoSizeChanged_revoker>(this, NaturalVideoSizeChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoSizeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->remove_NaturalVideoSizeChanged(get_abi(token)));
}

template <typename D> Windows::Media::Playback::MediaPlayer consume_Windows_Media_Playback_IMediaPlaybackSession<D>::MediaPlayer() const
{
    Windows::Media::Playback::MediaPlayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_MediaPlayer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlaybackSession<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::Position(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->put_Position(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackState consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackState() const
{
    Windows::Media::Playback::MediaPlaybackState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_PlaybackState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSession<D>::CanSeek() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_CanSeek(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSession<D>::CanPause() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_CanPause(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSession<D>::IsProtected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_IsProtected(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_PlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::PlaybackRate(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->put_PlaybackRate(value));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackSession<D>::BufferingProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_BufferingProgress(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackSession<D>::DownloadProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_DownloadProgress(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalVideoHeight(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NaturalVideoWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_NaturalVideoWidth(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NormalizedSourceRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_NormalizedSourceRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::NormalizedSourceRect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->put_NormalizedSourceRect(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::StereoscopicVideoPackingMode consume_Windows_Media_Playback_IMediaPlaybackSession<D>::StereoscopicVideoPackingMode() const
{
    Windows::Media::MediaProperties::StereoscopicVideoPackingMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->get_StereoscopicVideoPackingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession<D>::StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession)->put_StereoscopicVideoPackingMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->add_BufferedRangesChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferedRangesChanged_revoker>(this, BufferedRangesChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::BufferedRangesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->remove_BufferedRangesChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->add_PlayedRangesChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, PlayedRangesChanged_revoker>(this, PlayedRangesChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::PlayedRangesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->remove_PlayedRangesChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->add_SeekableRangesChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, SeekableRangesChanged_revoker>(this, SeekableRangesChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SeekableRangesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->remove_SeekableRangesChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->add_SupportedPlaybackRatesChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, SupportedPlaybackRatesChanged_revoker>(this, SupportedPlaybackRatesChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SupportedPlaybackRatesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->remove_SupportedPlaybackRatesChanged(get_abi(token)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackSphericalVideoProjection consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::SphericalVideoProjection() const
{
    Windows::Media::Playback::MediaPlaybackSphericalVideoProjection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->get_SphericalVideoProjection(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsMirroring() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->get_IsMirroring(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsMirroring(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->put_IsMirroring(value));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetBufferedRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->GetBufferedRanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetPlayedRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->GetPlayedRanges(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::GetSeekableRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->GetSeekableRanges(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSession2<D>::IsSupportedPlaybackRateRange(double rate1, double rate2) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession2)->IsSupportedPlaybackRateRange(rate1, rate2, &value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRotation consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::PlaybackRotation() const
{
    Windows::Media::MediaProperties::MediaRotation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession3)->get_PlaybackRotation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::PlaybackRotation(Windows::Media::MediaProperties::MediaRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession3)->put_PlaybackRotation(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState consume_Windows_Media_Playback_IMediaPlaybackSession3<D>::GetOutputDegradationPolicyState() const
{
    Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSession3)->GetOutputDegradationPolicyState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSessionBufferingStartedEventArgs<D>::IsPlaybackInterruption() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs)->get_IsPlaybackInterruption(&value));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason consume_Windows_Media_Playback_IMediaPlaybackSessionOutputDegradationPolicyState<D>::VideoConstrictionReason() const
{
    Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState)->get_VideoConstrictionReason(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_IsEnabled(value));
}

template <typename D> Windows::Media::MediaProperties::SphericalVideoFrameFormat consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::FrameFormat() const
{
    Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_FrameFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_FrameFormat(get_abi(value)));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::HorizontalFieldOfViewInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_HorizontalFieldOfViewInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::HorizontalFieldOfViewInDegrees(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_HorizontalFieldOfViewInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ViewOrientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_ViewOrientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ViewOrientation(Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_ViewOrientation(get_abi(value)));
}

template <typename D> Windows::Media::Playback::SphericalVideoProjectionMode consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ProjectionMode() const
{
    Windows::Media::Playback::SphericalVideoProjectionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->get_ProjectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackSphericalVideoProjection<D>::ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection)->put_ProjectionMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->add_PresentationModeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged_revoker consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PresentationModeChanged_revoker>(this, PresentationModeChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::PresentationModeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->remove_PresentationModeChanged(get_abi(token)));
}

template <typename D> Windows::Media::Playback::TimedMetadataTrackPresentationMode consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::GetPresentationMode(uint32_t index) const
{
    Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->GetPresentationMode(index, put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlaybackTimedMetadataTrackList<D>::SetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList)->SetPresentationMode(index, get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::AutoPlay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_AutoPlay(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::AutoPlay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_AutoPlay(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlayer<D>::NaturalDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_NaturalDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlayer<D>::Position() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::Position(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_Position(get_abi(value)));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingProgress() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_BufferingProgress(&value));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlayerState consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentState() const
{
    Windows::Media::Playback::MediaPlayerState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_CurrentState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::CanSeek() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_CanSeek(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::CanPause() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_CanPause(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::IsLoopingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_IsLoopingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::IsLoopingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_IsLoopingEnabled(value));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::IsProtected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_IsProtected(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer<D>::IsMuted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_IsMuted(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::IsMuted(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_IsMuted(value));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_PlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackRate(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_PlaybackRate(value));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlayer<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_Volume(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::Volume(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->put_Volume(value));
}

template <typename D> Windows::Media::Playback::PlaybackMediaMarkerSequence consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkers() const
{
    Windows::Media::Playback::PlaybackMediaMarkerSequence value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->get_PlaybackMediaMarkers(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_MediaOpened(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, MediaOpened_revoker>(this, MediaOpened(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::MediaOpened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_MediaOpened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_MediaEnded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, MediaEnded_revoker>(this, MediaEnded(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::MediaEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_MediaEnded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_MediaFailed(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MediaFailed_revoker>(this, MediaFailed(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::MediaFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_MediaFailed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_CurrentStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, CurrentStateChanged_revoker>(this, CurrentStateChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::CurrentStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_CurrentStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_PlaybackMediaMarkerReached(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, PlaybackMediaMarkerReached_revoker>(this, PlaybackMediaMarkerReached(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::PlaybackMediaMarkerReached(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_PlaybackMediaMarkerReached(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_MediaPlayerRateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MediaPlayerRateChanged_revoker>(this, MediaPlayerRateChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::MediaPlayerRateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_MediaPlayerRateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_VolumeChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, VolumeChanged_revoker>(this, VolumeChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::VolumeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_VolumeChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_SeekCompleted(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, SeekCompleted_revoker>(this, SeekCompleted(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::SeekCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_SeekCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_BufferingStarted(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferingStarted_revoker>(this, BufferingStarted(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_BufferingStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->add_BufferingEnded(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded_revoker consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, BufferingEnded_revoker>(this, BufferingEnded(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::BufferingEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->remove_BufferingEnded(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::Play() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->Play());
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->Pause());
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer<D>::SetUriSource(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer)->SetUriSource(get_abi(value)));
}

template <typename D> Windows::Media::SystemMediaTransportControls consume_Windows_Media_Playback_IMediaPlayer2<D>::SystemMediaTransportControls() const
{
    Windows::Media::SystemMediaTransportControls value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer2)->get_SystemMediaTransportControls(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlayerAudioCategory consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioCategory() const
{
    Windows::Media::Playback::MediaPlayerAudioCategory value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer2)->get_AudioCategory(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer2)->put_AudioCategory(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlayerAudioDeviceType consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioDeviceType() const
{
    Windows::Media::Playback::MediaPlayerAudioDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer2)->get_AudioDeviceType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer2<D>::AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer2)->put_AudioDeviceType(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->add_IsMutedChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged_revoker consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, IsMutedChanged_revoker>(this, IsMutedChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::IsMutedChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->remove_IsMutedChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->add_SourceChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged_revoker consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, SourceChanged_revoker>(this, SourceChanged(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::SourceChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->remove_SourceChanged(get_abi(token)));
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioBalance() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_AudioBalance(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioBalance(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_AudioBalance(value));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer3<D>::RealTimePlayback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_RealTimePlayback(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::RealTimePlayback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_RealTimePlayback(value));
}

template <typename D> Windows::Media::Playback::StereoscopicVideoRenderMode consume_Windows_Media_Playback_IMediaPlayer3<D>::StereoscopicVideoRenderMode() const
{
    Windows::Media::Playback::StereoscopicVideoRenderMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_StereoscopicVideoRenderMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_StereoscopicVideoRenderMode(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaBreakManager consume_Windows_Media_Playback_IMediaPlayer3<D>::BreakManager() const
{
    Windows::Media::Playback::MediaBreakManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_BreakManager(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackCommandManager consume_Windows_Media_Playback_IMediaPlayer3<D>::CommandManager() const
{
    Windows::Media::Playback::MediaPlaybackCommandManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_CommandManager(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioDevice() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_AudioDevice(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::AudioDevice(Windows::Devices::Enumeration::DeviceInformation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_AudioDevice(get_abi(value)));
}

template <typename D> Windows::Media::MediaTimelineController consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineController() const
{
    Windows::Media::MediaTimelineController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_TimelineController(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineController(Windows::Media::MediaTimelineController const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_TimelineController(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineControllerPositionOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_TimelineControllerPositionOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::TimelineControllerPositionOffset(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->put_TimelineControllerPositionOffset(get_abi(value)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackSession consume_Windows_Media_Playback_IMediaPlayer3<D>::PlaybackSession() const
{
    Windows::Media::Playback::MediaPlaybackSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->get_PlaybackSession(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::StepForwardOneFrame() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->StepForwardOneFrame());
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer3<D>::StepBackwardOneFrame() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->StepBackwardOneFrame());
}

template <typename D> Windows::Media::Casting::CastingSource consume_Windows_Media_Playback_IMediaPlayer3<D>::GetAsCastingSource() const
{
    Windows::Media::Casting::CastingSource returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer3)->GetAsCastingSource(put_abi(returnValue)));
    return returnValue;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer4<D>::SetSurfaceSize(Windows::Foundation::Size const& size) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer4)->SetSurfaceSize(get_abi(size)));
}

template <typename D> Windows::Media::Playback::MediaPlayerSurface consume_Windows_Media_Playback_IMediaPlayer4<D>::GetSurface(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::Media::Playback::MediaPlayerSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer4)->GetSurface(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->add_VideoFrameAvailable(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable_revoker consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, VideoFrameAvailable_revoker>(this, VideoFrameAvailable(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer5<D>::VideoFrameAvailable(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->remove_VideoFrameAvailable(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer5<D>::IsVideoFrameServerEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->get_IsVideoFrameServerEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer5<D>::IsVideoFrameServerEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->put_IsVideoFrameServerEnabled(value));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToVideoSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->CopyFrameToVideoSurface(get_abi(destination)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToVideoSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, Windows::Foundation::Rect const& targetRectangle) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->CopyFrameToVideoSurfaceWithTargetRectangle(get_abi(destination), get_abi(targetRectangle)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer5<D>::CopyFrameToStereoscopicVideoSurfaces(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationLeftEye, Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destinationRightEye) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer5)->CopyFrameToStereoscopicVideoSurfaces(get_abi(destinationLeftEye), get_abi(destinationRightEye)));
}

template <typename D> winrt::event_token consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer6)->add_SubtitleFrameChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged_revoker consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SubtitleFrameChanged_revoker>(this, SubtitleFrameChanged(handler));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayer6<D>::SubtitleFrameChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Playback::IMediaPlayer6)->remove_SubtitleFrameChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer6<D>::RenderSubtitlesToSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer6)->RenderSubtitlesToSurface(get_abi(destination), &result));
    return result;
}

template <typename D> bool consume_Windows_Media_Playback_IMediaPlayer6<D>::RenderSubtitlesToSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& destination, Windows::Foundation::Rect const& targetRectangle) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer6)->RenderSubtitlesToSurfaceWithTargetRectangle(get_abi(destination), get_abi(targetRectangle), &result));
    return result;
}

template <typename D> Windows::Media::Audio::AudioStateMonitor consume_Windows_Media_Playback_IMediaPlayer7<D>::AudioStateMonitor() const
{
    Windows::Media::Audio::AudioStateMonitor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayer7)->get_AudioStateMonitor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Media_Playback_IMediaPlayerDataReceivedEventArgs<D>::Data() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerEffects<D>::AddAudioEffect(param::hstring const& activatableClassId, bool effectOptional, Windows::Foundation::Collections::IPropertySet const& configuration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerEffects)->AddAudioEffect(get_abi(activatableClassId), effectOptional, get_abi(configuration)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerEffects<D>::RemoveAllEffects() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerEffects)->RemoveAllEffects());
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerEffects2<D>::AddVideoEffect(param::hstring const& activatableClassId, bool effectOptional, Windows::Foundation::Collections::IPropertySet const& effectConfiguration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerEffects2)->AddVideoEffect(get_abi(activatableClassId), effectOptional, get_abi(effectConfiguration)));
}

template <typename D> Windows::Media::Playback::MediaPlayerError consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::Error() const
{
    Windows::Media::Playback::MediaPlayerError value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::ExtendedErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_ExtendedErrorCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Playback_IMediaPlayerFailedEventArgs<D>::ErrorMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerFailedEventArgs)->get_ErrorMessage(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_Playback_IMediaPlayerRateChangedEventArgs<D>::NewRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerRateChangedEventArgs)->get_NewRate(&value));
    return value;
}

template <typename D> Windows::Media::Protection::MediaProtectionManager consume_Windows_Media_Playback_IMediaPlayerSource<D>::ProtectionManager() const
{
    Windows::Media::Protection::MediaProtectionManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource)->get_ProtectionManager(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerSource<D>::ProtectionManager(Windows::Media::Protection::MediaProtectionManager const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource)->put_ProtectionManager(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetFileSource(Windows::Storage::IStorageFile const& file) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource)->SetFileSource(get_abi(file)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetStreamSource(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource)->SetStreamSource(get_abi(stream)));
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerSource<D>::SetMediaSource(Windows::Media::Core::IMediaSource const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource)->SetMediaSource(get_abi(source)));
}

template <typename D> Windows::Media::Playback::IMediaPlaybackSource consume_Windows_Media_Playback_IMediaPlayerSource2<D>::Source() const
{
    Windows::Media::Playback::IMediaPlaybackSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource2)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IMediaPlayerSource2<D>::Source(Windows::Media::Playback::IMediaPlaybackSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSource2)->put_Source(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ICompositionSurface consume_Windows_Media_Playback_IMediaPlayerSurface<D>::CompositionSurface() const
{
    Windows::UI::Composition::ICompositionSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSurface)->get_CompositionSurface(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Compositor consume_Windows_Media_Playback_IMediaPlayerSurface<D>::Compositor() const
{
    Windows::UI::Composition::Compositor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSurface)->get_Compositor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlayer consume_Windows_Media_Playback_IMediaPlayerSurface<D>::MediaPlayer() const
{
    Windows::Media::Playback::MediaPlayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IMediaPlayerSurface)->get_MediaPlayer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::Time() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarker)->get_Time(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::MediaMarkerType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarker)->get_MediaMarkerType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Playback_IPlaybackMediaMarker<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarker)->get_Text(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::PlaybackMediaMarker consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory<D>::CreateFromTime(Windows::Foundation::TimeSpan const& value) const
{
    Windows::Media::Playback::PlaybackMediaMarker marker{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerFactory)->CreateFromTime(get_abi(value), put_abi(marker)));
    return marker;
}

template <typename D> Windows::Media::Playback::PlaybackMediaMarker consume_Windows_Media_Playback_IPlaybackMediaMarkerFactory<D>::Create(Windows::Foundation::TimeSpan const& value, param::hstring const& mediaMarketType, param::hstring const& text) const
{
    Windows::Media::Playback::PlaybackMediaMarker marker{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerFactory)->Create(get_abi(value), get_abi(mediaMarketType), get_abi(text), put_abi(marker)));
    return marker;
}

template <typename D> Windows::Media::Playback::PlaybackMediaMarker consume_Windows_Media_Playback_IPlaybackMediaMarkerReachedEventArgs<D>::PlaybackMediaMarker() const
{
    Windows::Media::Playback::PlaybackMediaMarker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs)->get_PlaybackMediaMarker(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Size() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerSequence)->get_Size(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Insert(Windows::Media::Playback::PlaybackMediaMarker const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerSequence)->Insert(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Playback_IPlaybackMediaMarkerSequence<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Playback::IPlaybackMediaMarkerSequence)->Clear());
}

template <typename D> Windows::Media::Core::TimedMetadataTrack consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::Track() const
{
    Windows::Media::Core::TimedMetadataTrack value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_Track(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::TimedMetadataTrackPresentationMode consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::OldPresentationMode() const
{
    Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_OldPresentationMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::TimedMetadataTrackPresentationMode consume_Windows_Media_Playback_ITimedMetadataPresentationModeChangedEventArgs<D>::NewPresentationMode() const
{
    Windows::Media::Playback::TimedMetadataTrackPresentationMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs)->get_NewPresentationMode(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Playback::IBackgroundMediaPlayerStatics> : produce_base<D, Windows::Media::Playback::IBackgroundMediaPlayerStatics>
{
    int32_t WINRT_CALL get_Current(void** player) noexcept final
    {
        try
        {
            *player = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Media::Playback::MediaPlayer));
            *player = detach_from<Windows::Media::Playback::MediaPlayer>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MessageReceivedFromBackground(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceivedFromBackground, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageReceivedFromBackground(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceivedFromBackground(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceivedFromBackground, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceivedFromBackground(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MessageReceivedFromForeground(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageReceivedFromForeground, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageReceivedFromForeground(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageReceivedFromForeground(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageReceivedFromForeground, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageReceivedFromForeground(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SendMessageToBackground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageToBackground, WINRT_WRAP(void), Windows::Foundation::Collections::ValueSet const&);
            this->shim().SendMessageToBackground(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageToForeground(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageToForeground, WINRT_WRAP(void), Windows::Foundation::Collections::ValueSet const&);
            this->shim().SendMessageToForeground(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsMediaPlaying(bool* isMediaPlaying) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMediaPlaying, WINRT_WRAP(bool));
            *isMediaPlaying = detach_from<bool>(this->shim().IsMediaPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Shutdown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shutdown, WINRT_WRAP(void));
            this->shim().Shutdown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> : produce_base<D, Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs>
{
    int32_t WINRT_CALL get_NewItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().NewItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().OldItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> : produce_base<D, Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2>
{
    int32_t WINRT_CALL get_Reason(Windows::Media::Playback::MediaPlaybackItemChangedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItemChangedReason));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItemChangedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreak> : produce_base<D, Windows::Media::Playback::IMediaBreak>
{
    int32_t WINRT_CALL get_PlaybackList(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackList, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackList));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackList>(this->shim().PlaybackList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationPosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationPosition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().PresentationPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InsertionMethod(Windows::Media::Playback::MediaBreakInsertionMethod* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertionMethod, WINRT_WRAP(Windows::Media::Playback::MediaBreakInsertionMethod));
            *value = detach_from<Windows::Media::Playback::MediaBreakInsertionMethod>(this->shim().InsertionMethod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomProperties, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().CustomProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanStart(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanStart, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanStart(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanStart, WINRT_WRAP(void), bool);
            this->shim().CanStart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakEndedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaBreakEndedEventArgs>
{
    int32_t WINRT_CALL get_MediaBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakFactory> : produce_base<D, Windows::Media::Playback::IMediaBreakFactory>
{
    int32_t WINRT_CALL Create(Windows::Media::Playback::MediaBreakInsertionMethod insertionMethod, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Playback::MediaBreak), Windows::Media::Playback::MediaBreakInsertionMethod const&);
            *result = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().Create(*reinterpret_cast<Windows::Media::Playback::MediaBreakInsertionMethod const*>(&insertionMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPresentationPosition(Windows::Media::Playback::MediaBreakInsertionMethod insertionMethod, Windows::Foundation::TimeSpan presentationPosition, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPresentationPosition, WINRT_WRAP(Windows::Media::Playback::MediaBreak), Windows::Media::Playback::MediaBreakInsertionMethod const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().CreateWithPresentationPosition(*reinterpret_cast<Windows::Media::Playback::MediaBreakInsertionMethod const*>(&insertionMethod), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&presentationPosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakManager> : produce_base<D, Windows::Media::Playback::IMediaBreakManager>
{
    int32_t WINRT_CALL add_BreaksSeekedOver(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreaksSeekedOver, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BreaksSeekedOver(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSeekedOverEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BreaksSeekedOver(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BreaksSeekedOver, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BreaksSeekedOver(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BreakStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreakStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BreakStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BreakStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BreakStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BreakStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BreakEnded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreakEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BreakEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakEndedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BreakEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BreakEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BreakEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BreakSkipped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreakSkipped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BreakSkipped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakManager, Windows::Media::Playback::MediaBreakSkippedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BreakSkipped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BreakSkipped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BreakSkipped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_CurrentBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().CurrentBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackSession, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackSession));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackSession>(this->shim().PlaybackSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PlayBreak(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayBreak, WINRT_WRAP(void), Windows::Media::Playback::MediaBreak const&);
            this->shim().PlayBreak(*reinterpret_cast<Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SkipCurrentBreak() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkipCurrentBreak, WINRT_WRAP(void));
            this->shim().SkipCurrentBreak();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakSchedule> : produce_base<D, Windows::Media::Playback::IMediaBreakSchedule>
{
    int32_t WINRT_CALL add_ScheduleChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScheduleChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ScheduleChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaBreakSchedule, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScheduleChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScheduleChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScheduleChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL InsertMidrollBreak(void* mediaBreak) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertMidrollBreak, WINRT_WRAP(void), Windows::Media::Playback::MediaBreak const&);
            this->shim().InsertMidrollBreak(*reinterpret_cast<Windows::Media::Playback::MediaBreak const*>(&mediaBreak));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveMidrollBreak(void* mediaBreak) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveMidrollBreak, WINRT_WRAP(void), Windows::Media::Playback::MediaBreak const&);
            this->shim().RemoveMidrollBreak(*reinterpret_cast<Windows::Media::Playback::MediaBreak const*>(&mediaBreak));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MidrollBreaks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MidrollBreaks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak>>(this->shim().MidrollBreaks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrerollBreak(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrerollBreak, WINRT_WRAP(void), Windows::Media::Playback::MediaBreak const&);
            this->shim().PrerollBreak(*reinterpret_cast<Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrerollBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrerollBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().PrerollBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PostrollBreak(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostrollBreak, WINRT_WRAP(void), Windows::Media::Playback::MediaBreak const&);
            this->shim().PostrollBreak(*reinterpret_cast<Windows::Media::Playback::MediaBreak const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostrollBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostrollBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().PostrollBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().PlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> : produce_base<D, Windows::Media::Playback::IMediaBreakSeekedOverEventArgs>
{
    int32_t WINRT_CALL get_SeekedOverBreaks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeekedOverBreaks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaBreak>>(this->shim().SeekedOverBreaks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldPosition(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldPosition, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().OldPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewPosition(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewPosition, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().NewPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakSkippedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaBreakSkippedEventArgs>
{
    int32_t WINRT_CALL get_MediaBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaBreakStartedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaBreakStartedEventArgs>
{
    int32_t WINRT_CALL get_MediaBreak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaBreak, WINRT_WRAP(Windows::Media::Playback::MediaBreak));
            *value = detach_from<Windows::Media::Playback::MediaBreak>(this->shim().MediaBreak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaEnginePlaybackSource> : produce_base<D, Windows::Media::Playback::IMediaEnginePlaybackSource>
{
    int32_t WINRT_CALL get_CurrentItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPlaybackSource(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPlaybackSource, WINRT_WRAP(void), Windows::Media::Playback::IMediaPlaybackSource const&);
            this->shim().SetPlaybackSource(*reinterpret_cast<Windows::Media::Playback::IMediaPlaybackSource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaItemDisplayProperties> : produce_base<D, Windows::Media::Playback::IMediaItemDisplayProperties>
{
    int32_t WINRT_CALL get_Type(Windows::Media::MediaPlaybackType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Media::MediaPlaybackType));
            *value = detach_from<Windows::Media::MediaPlaybackType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(Windows::Media::MediaPlaybackType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), Windows::Media::MediaPlaybackType const&);
            this->shim().Type(*reinterpret_cast<Windows::Media::MediaPlaybackType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MusicProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MusicProperties, WINRT_WRAP(Windows::Media::MusicDisplayProperties));
            *value = detach_from<Windows::Media::MusicDisplayProperties>(this->shim().MusicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProperties, WINRT_WRAP(Windows::Media::VideoDisplayProperties));
            *value = detach_from<Windows::Media::VideoDisplayProperties>(this->shim().VideoProperties());
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
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::RandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::RandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::RandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAll, WINRT_WRAP(void));
            this->shim().ClearAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManager> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManager>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPlayer, WINRT_WRAP(Windows::Media::Playback::MediaPlayer));
            *value = detach_from<Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlayBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PlayBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PauseBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PauseBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().NextBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviousBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PreviousBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FastForwardBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FastForwardBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().FastForwardBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RewindBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RewindBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().RewindBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShuffleBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().ShuffleBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRepeatModeBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatModeBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().AutoRepeatModeBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().PositionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RateBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RateBehavior, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior>(this->shim().RateBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PlayReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlayReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlayReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlayReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlayReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PauseReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PauseReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PauseReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PauseReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PauseReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NextReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NextReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NextReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NextReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NextReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PreviousReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PreviousReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PreviousReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PreviousReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PreviousReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FastForwardReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FastForwardReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FastForwardReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FastForwardReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FastForwardReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FastForwardReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RewindReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RewindReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RewindReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RewindReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RewindReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RewindReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ShuffleReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShuffleReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShuffleReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShuffleReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShuffleReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AutoRepeatModeReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatModeReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AutoRepeatModeReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AutoRepeatModeReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AutoRepeatModeReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AutoRepeatModeReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PositionReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PositionReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RateReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RateReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RateReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManager, Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RateReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RateReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RateReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRepeatMode(Windows::Media::MediaPlaybackAutoRepeatMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatMode, WINRT_WRAP(Windows::Media::MediaPlaybackAutoRepeatMode));
            *value = detach_from<Windows::Media::MediaPlaybackAutoRepeatMode>(this->shim().AutoRepeatMode());
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior>
{
    int32_t WINRT_CALL get_CommandManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandManager, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManager));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManager>(this->shim().CommandManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnablingRule, WINRT_WRAP(Windows::Media::Playback::MediaCommandEnablingRule));
            *value = detach_from<Windows::Media::Playback::MediaCommandEnablingRule>(this->shim().EnablingRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnablingRule(Windows::Media::Playback::MediaCommandEnablingRule value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnablingRule, WINRT_WRAP(void), Windows::Media::Playback::MediaCommandEnablingRule const&);
            this->shim().EnablingRule(*reinterpret_cast<Windows::Media::Playback::MediaCommandEnablingRule const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsEnabledChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PlaybackRate());
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsShuffleRequested(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShuffleRequested, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsShuffleRequested());
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
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItem> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItem>
{
    int32_t WINRT_CALL add_AudioTracksChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioTracksChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioTracksChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioTracksChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioTracksChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VideoTracksChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoTracksChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoTracksChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoTracksChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoTracksChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TimedMetadataTracksChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimedMetadataTracksChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TimedMetadataTracksChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackItem, Windows::Foundation::Collections::IVectorChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TimedMetadataTracksChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TimedMetadataTracksChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TimedMetadataTracksChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Media::Core::MediaSource));
            *value = detach_from<Windows::Media::Core::MediaSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioTracks, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackAudioTrackList));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackAudioTrackList>(this->shim().AudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoTracks, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackVideoTrackList));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackVideoTrackList>(this->shim().VideoTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimedMetadataTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimedMetadataTracks, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList>(this->shim().TimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItem2> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItem2>
{
    int32_t WINRT_CALL get_BreakSchedule(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreakSchedule, WINRT_WRAP(Windows::Media::Playback::MediaBreakSchedule));
            *value = detach_from<Windows::Media::Playback::MediaBreakSchedule>(this->shim().BreakSchedule());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_DurationLimit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DurationLimit, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().DurationLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSkip(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSkip, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSkip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanSkip(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSkip, WINRT_WRAP(void), bool);
            this->shim().CanSkip(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDisplayProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDisplayProperties, WINRT_WRAP(Windows::Media::Playback::MediaItemDisplayProperties));
            *value = detach_from<Windows::Media::Playback::MediaItemDisplayProperties>(this->shim().GetDisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyDisplayProperties(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyDisplayProperties, WINRT_WRAP(void), Windows::Media::Playback::MediaItemDisplayProperties const&);
            this->shim().ApplyDisplayProperties(*reinterpret_cast<Windows::Media::Playback::MediaItemDisplayProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItem3> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItem3>
{
    int32_t WINRT_CALL get_IsDisabledInPlaybackList(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledInPlaybackList, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledInPlaybackList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDisabledInPlaybackList(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledInPlaybackList, WINRT_WRAP(void), bool);
            this->shim().IsDisabledInPlaybackList(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalDownloadProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalDownloadProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TotalDownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoLoadedDisplayProperties, WINRT_WRAP(Windows::Media::Playback::AutoLoadedDisplayPropertyKind));
            *value = detach_from<Windows::Media::Playback::AutoLoadedDisplayPropertyKind>(this->shim().AutoLoadedDisplayProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoLoadedDisplayProperties(Windows::Media::Playback::AutoLoadedDisplayPropertyKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoLoadedDisplayProperties, WINRT_WRAP(void), Windows::Media::Playback::AutoLoadedDisplayPropertyKind const&);
            this->shim().AutoLoadedDisplayProperties(*reinterpret_cast<Windows::Media::Playback::AutoLoadedDisplayPropertyKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemError> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemError>
{
    int32_t WINRT_CALL get_ErrorCode(Windows::Media::Playback::MediaPlaybackItemErrorCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItemErrorCode));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItemErrorCode>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemFactory> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemFactory>
{
    int32_t WINRT_CALL Create(void* source, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem), Windows::Media::Core::MediaSource const&);
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().Create(*reinterpret_cast<Windows::Media::Core::MediaSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemFactory2> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemFactory2>
{
    int32_t WINRT_CALL CreateWithStartTime(void* source, Windows::Foundation::TimeSpan startTime, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithStartTime, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem), Windows::Media::Core::MediaSource const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().CreateWithStartTime(*reinterpret_cast<Windows::Media::Core::MediaSource const*>(&source), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithStartTimeAndDurationLimit(void* source, Windows::Foundation::TimeSpan startTime, Windows::Foundation::TimeSpan durationLimit, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithStartTimeAndDurationLimit, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem), Windows::Media::Core::MediaSource const&, Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().CreateWithStartTimeAndDurationLimit(*reinterpret_cast<Windows::Media::Core::MediaSource const*>(&source), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&durationLimit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs>
{
    int32_t WINRT_CALL get_Item(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Item, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Error(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItemError));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItemError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs>
{
    int32_t WINRT_CALL get_Item(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Item, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackItemStatics> : produce_base<D, Windows::Media::Playback::IMediaPlaybackItemStatics>
{
    int32_t WINRT_CALL FindFromMediaSource(void* source, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindFromMediaSource, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem), Windows::Media::Core::MediaSource const&);
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().FindFromMediaSource(*reinterpret_cast<Windows::Media::Core::MediaSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackList> : produce_base<D, Windows::Media::Playback::IMediaPlaybackList>
{
    int32_t WINRT_CALL add_ItemFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CurrentItemChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentItemChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentItemChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentItemChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentItemChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentItemChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ItemOpened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemOpened, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemOpened(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackList, Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemOpened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemOpened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Media::Playback::MediaPlaybackItem>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Media::Playback::MediaPlaybackItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoRepeatEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoRepeatEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoRepeatEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoRepeatEnabled, WINRT_WRAP(void), bool);
            this->shim().AutoRepeatEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShuffleEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShuffleEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShuffleEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffleEnabled, WINRT_WRAP(void), bool);
            this->shim().ShuffleEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentItemIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentItemIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CurrentItemIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveNext(void** item) noexcept final
    {
        try
        {
            *item = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveNext, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *item = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().MoveNext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MovePrevious(void** item) noexcept final
    {
        try
        {
            *item = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MovePrevious, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *item = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().MovePrevious());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveTo(uint32_t itemIndex, void** item) noexcept final
    {
        try
        {
            *item = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveTo, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem), uint32_t);
            *item = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().MoveTo(itemIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackList2> : produce_base<D, Windows::Media::Playback::IMediaPlaybackList2>
{
    int32_t WINRT_CALL get_MaxPrefetchTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPrefetchTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MaxPrefetchTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPrefetchTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPrefetchTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().MaxPrefetchTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartingItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartingItem, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackItem));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackItem>(this->shim().StartingItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartingItem(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartingItem, WINRT_WRAP(void), Windows::Media::Playback::MediaPlaybackItem const&);
            this->shim().StartingItem(*reinterpret_cast<Windows::Media::Playback::MediaPlaybackItem const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShuffledItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShuffledItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaPlaybackItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Playback::MediaPlaybackItem>>(this->shim().ShuffledItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetShuffledItems(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetShuffledItems, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Media::Playback::MediaPlaybackItem> const&);
            this->shim().SetShuffledItems(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Playback::MediaPlaybackItem> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackList3> : produce_base<D, Windows::Media::Playback::IMediaPlaybackList3>
{
    int32_t WINRT_CALL get_MaxPlayedItemsToKeepOpen(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPlayedItemsToKeepOpen, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxPlayedItemsToKeepOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPlayedItemsToKeepOpen(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPlayedItemsToKeepOpen, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().MaxPlayedItemsToKeepOpen(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSession> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSession>
{
    int32_t WINRT_CALL add_PlaybackStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackRateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackRateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackRateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackRateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SeekCompleted(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeekCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SeekCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SeekCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SeekCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SeekCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BufferingStarted(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferingStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferingStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferingStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferingStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BufferingEnded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferingEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferingEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferingEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferingEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BufferingProgressChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingProgressChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferingProgressChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferingProgressChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferingProgressChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferingProgressChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadProgressChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProgressChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadProgressChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadProgressChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadProgressChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadProgressChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NaturalDurationChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalDurationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().NaturalDurationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NaturalDurationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NaturalDurationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NaturalDurationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PositionChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NaturalVideoSizeChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalVideoSizeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().NaturalVideoSizeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NaturalVideoSizeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NaturalVideoSizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NaturalVideoSizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPlayer, WINRT_WRAP(Windows::Media::Playback::MediaPlayer));
            *value = detach_from<Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().NaturalDuration());
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

    int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackState(Windows::Media::Playback::MediaPlaybackState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackState, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackState));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackState>(this->shim().PlaybackState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSeek(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSeek, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanPause(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPause, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanPause());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsProtected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackRate(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(void), double);
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferingProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BufferingProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DownloadProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalVideoHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalVideoHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NaturalVideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalVideoWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalVideoWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NaturalVideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedSourceRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedSourceRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().NormalizedSourceRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalizedSourceRect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedSourceRect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().NormalizedSourceRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoscopicVideoPackingMode, WINRT_WRAP(Windows::Media::MediaProperties::StereoscopicVideoPackingMode));
            *value = detach_from<Windows::Media::MediaProperties::StereoscopicVideoPackingMode>(this->shim().StereoscopicVideoPackingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoscopicVideoPackingMode, WINRT_WRAP(void), Windows::Media::MediaProperties::StereoscopicVideoPackingMode const&);
            this->shim().StereoscopicVideoPackingMode(*reinterpret_cast<Windows::Media::MediaProperties::StereoscopicVideoPackingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSession2> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSession2>
{
    int32_t WINRT_CALL add_BufferedRangesChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferedRangesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferedRangesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferedRangesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferedRangesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferedRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlayedRangesChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayedRangesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlayedRangesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlayedRangesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlayedRangesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlayedRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SeekableRangesChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeekableRangesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SeekableRangesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SeekableRangesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SeekableRangesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SeekableRangesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SupportedPlaybackRatesChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPlaybackRatesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SupportedPlaybackRatesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackSession, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SupportedPlaybackRatesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SupportedPlaybackRatesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SupportedPlaybackRatesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_SphericalVideoProjection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SphericalVideoProjection, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackSphericalVideoProjection));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackSphericalVideoProjection>(this->shim().SphericalVideoProjection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMirroring(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMirroring, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMirroring(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMirroring, WINRT_WRAP(void), bool);
            this->shim().IsMirroring(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBufferedRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBufferedRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>>(this->shim().GetBufferedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPlayedRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPlayedRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>>(this->shim().GetPlayedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSeekableRanges(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSeekableRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::MediaTimeRange>>(this->shim().GetSeekableRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSupportedPlaybackRateRange(double rate1, double rate2, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupportedPlaybackRateRange, WINRT_WRAP(bool), double, double);
            *value = detach_from<bool>(this->shim().IsSupportedPlaybackRateRange(rate1, rate2));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSession3> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSession3>
{
    int32_t WINRT_CALL get_PlaybackRotation(Windows::Media::MediaProperties::MediaRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRotation, WINRT_WRAP(Windows::Media::MediaProperties::MediaRotation));
            *value = detach_from<Windows::Media::MediaProperties::MediaRotation>(this->shim().PlaybackRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackRotation(Windows::Media::MediaProperties::MediaRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRotation, WINRT_WRAP(void), Windows::Media::MediaProperties::MediaRotation const&);
            this->shim().PlaybackRotation(*reinterpret_cast<Windows::Media::MediaProperties::MediaRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOutputDegradationPolicyState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOutputDegradationPolicyState, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState>(this->shim().GetOutputDegradationPolicyState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs>
{
    int32_t WINRT_CALL get_IsPlaybackInterruption(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaybackInterruption, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlaybackInterruption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState>
{
    int32_t WINRT_CALL get_VideoConstrictionReason(Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoConstrictionReason, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackSessionVideoConstrictionReason>(this->shim().VideoConstrictionReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSource> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSource>
{};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> : produce_base<D, Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameFormat, WINRT_WRAP(Windows::Media::MediaProperties::SphericalVideoFrameFormat));
            *value = detach_from<Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().FrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameFormat, WINRT_WRAP(void), Windows::Media::MediaProperties::SphericalVideoFrameFormat const&);
            this->shim().FrameFormat(*reinterpret_cast<Windows::Media::MediaProperties::SphericalVideoFrameFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalFieldOfViewInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalFieldOfViewInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalFieldOfViewInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalFieldOfViewInDegrees(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalFieldOfViewInDegrees, WINRT_WRAP(void), double);
            this->shim().HorizontalFieldOfViewInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewOrientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().ViewOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewOrientation(Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewOrientation, WINRT_WRAP(void), Windows::Foundation::Numerics::quaternion const&);
            this->shim().ViewOrientation(*reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMode, WINRT_WRAP(Windows::Media::Playback::SphericalVideoProjectionMode));
            *value = detach_from<Windows::Media::Playback::SphericalVideoProjectionMode>(this->shim().ProjectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProjectionMode(Windows::Media::Playback::SphericalVideoProjectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionMode, WINRT_WRAP(void), Windows::Media::Playback::SphericalVideoProjectionMode const&);
            this->shim().ProjectionMode(*reinterpret_cast<Windows::Media::Playback::SphericalVideoProjectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> : produce_base<D, Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList>
{
    int32_t WINRT_CALL add_PresentationModeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationModeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PresentationModeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList, Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PresentationModeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PresentationModeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PresentationModeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPresentationMode, WINRT_WRAP(Windows::Media::Playback::TimedMetadataTrackPresentationMode), uint32_t);
            *value = detach_from<Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().GetPresentationMode(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPresentationMode(uint32_t index, Windows::Media::Playback::TimedMetadataTrackPresentationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPresentationMode, WINRT_WRAP(void), uint32_t, Windows::Media::Playback::TimedMetadataTrackPresentationMode const&);
            this->shim().SetPresentationMode(index, *reinterpret_cast<Windows::Media::Playback::TimedMetadataTrackPresentationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer> : produce_base<D, Windows::Media::Playback::IMediaPlayer>
{
    int32_t WINRT_CALL get_AutoPlay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoPlay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(void), bool);
            this->shim().AutoPlay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().NaturalDuration());
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

    int32_t WINRT_CALL put_Position(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferingProgress(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingProgress, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BufferingProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentState(Windows::Media::Playback::MediaPlayerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentState, WINRT_WRAP(Windows::Media::Playback::MediaPlayerState));
            *value = detach_from<Windows::Media::Playback::MediaPlayerState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSeek(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSeek, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanPause(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPause, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanPause());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLoopingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLoopingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLoopingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLoopingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLoopingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsLoopingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsProtected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProtected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMuted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMuted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMuted(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMuted, WINRT_WRAP(void), bool);
            this->shim().IsMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackRate(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(void), double);
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Volume(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Volume(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(void), double);
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackMediaMarkers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackMediaMarkers, WINRT_WRAP(Windows::Media::Playback::PlaybackMediaMarkerSequence));
            *value = detach_from<Windows::Media::Playback::PlaybackMediaMarkerSequence>(this->shim().PlaybackMediaMarkers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MediaOpened(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaOpened, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaOpened(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaOpened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaOpened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MediaEnded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MediaFailed(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerFailedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CurrentStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackMediaMarkerReached(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackMediaMarkerReached, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackMediaMarkerReached(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackMediaMarkerReached(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackMediaMarkerReached, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackMediaMarkerReached(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MediaPlayerRateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPlayerRateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MediaPlayerRateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Media::Playback::MediaPlayerRateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MediaPlayerRateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MediaPlayerRateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MediaPlayerRateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VolumeChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VolumeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VolumeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VolumeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VolumeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VolumeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SeekCompleted(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeekCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SeekCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SeekCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SeekCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SeekCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BufferingStarted(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferingStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferingStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferingStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferingStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BufferingEnded(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferingEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BufferingEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BufferingEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BufferingEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BufferingEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Play() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Play, WINRT_WRAP(void));
            this->shim().Play();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetUriSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetUriSource, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SetUriSource(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer2> : produce_base<D, Windows::Media::Playback::IMediaPlayer2>
{
    int32_t WINRT_CALL get_SystemMediaTransportControls(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemMediaTransportControls, WINRT_WRAP(Windows::Media::SystemMediaTransportControls));
            *value = detach_from<Windows::Media::SystemMediaTransportControls>(this->shim().SystemMediaTransportControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioCategory, WINRT_WRAP(Windows::Media::Playback::MediaPlayerAudioCategory));
            *value = detach_from<Windows::Media::Playback::MediaPlayerAudioCategory>(this->shim().AudioCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioCategory(Windows::Media::Playback::MediaPlayerAudioCategory value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioCategory, WINRT_WRAP(void), Windows::Media::Playback::MediaPlayerAudioCategory const&);
            this->shim().AudioCategory(*reinterpret_cast<Windows::Media::Playback::MediaPlayerAudioCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceType, WINRT_WRAP(Windows::Media::Playback::MediaPlayerAudioDeviceType));
            *value = detach_from<Windows::Media::Playback::MediaPlayerAudioDeviceType>(this->shim().AudioDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioDeviceType(Windows::Media::Playback::MediaPlayerAudioDeviceType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceType, WINRT_WRAP(void), Windows::Media::Playback::MediaPlayerAudioDeviceType const&);
            this->shim().AudioDeviceType(*reinterpret_cast<Windows::Media::Playback::MediaPlayerAudioDeviceType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer3> : produce_base<D, Windows::Media::Playback::IMediaPlayer3>
{
    int32_t WINRT_CALL add_IsMutedChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMutedChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsMutedChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsMutedChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsMutedChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsMutedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_AudioBalance(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioBalance, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AudioBalance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioBalance(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioBalance, WINRT_WRAP(void), double);
            this->shim().AudioBalance(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RealTimePlayback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RealTimePlayback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RealTimePlayback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RealTimePlayback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RealTimePlayback, WINRT_WRAP(void), bool);
            this->shim().RealTimePlayback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoscopicVideoRenderMode, WINRT_WRAP(Windows::Media::Playback::StereoscopicVideoRenderMode));
            *value = detach_from<Windows::Media::Playback::StereoscopicVideoRenderMode>(this->shim().StereoscopicVideoRenderMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StereoscopicVideoRenderMode(Windows::Media::Playback::StereoscopicVideoRenderMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoscopicVideoRenderMode, WINRT_WRAP(void), Windows::Media::Playback::StereoscopicVideoRenderMode const&);
            this->shim().StereoscopicVideoRenderMode(*reinterpret_cast<Windows::Media::Playback::StereoscopicVideoRenderMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BreakManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BreakManager, WINRT_WRAP(Windows::Media::Playback::MediaBreakManager));
            *value = detach_from<Windows::Media::Playback::MediaBreakManager>(this->shim().BreakManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandManager, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackCommandManager));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackCommandManager>(this->shim().CommandManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDevice, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().AudioDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioDevice(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDevice, WINRT_WRAP(void), Windows::Devices::Enumeration::DeviceInformation const&);
            this->shim().AudioDevice(*reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimelineController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimelineController, WINRT_WRAP(Windows::Media::MediaTimelineController));
            *value = detach_from<Windows::Media::MediaTimelineController>(this->shim().TimelineController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TimelineController(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimelineController, WINRT_WRAP(void), Windows::Media::MediaTimelineController const&);
            this->shim().TimelineController(*reinterpret_cast<Windows::Media::MediaTimelineController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimelineControllerPositionOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimelineControllerPositionOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TimelineControllerPositionOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TimelineControllerPositionOffset(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimelineControllerPositionOffset, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TimelineControllerPositionOffset(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaybackSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackSession, WINRT_WRAP(Windows::Media::Playback::MediaPlaybackSession));
            *value = detach_from<Windows::Media::Playback::MediaPlaybackSession>(this->shim().PlaybackSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StepForwardOneFrame() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StepForwardOneFrame, WINRT_WRAP(void));
            this->shim().StepForwardOneFrame();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StepBackwardOneFrame() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StepBackwardOneFrame, WINRT_WRAP(void));
            this->shim().StepBackwardOneFrame();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAsCastingSource(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsCastingSource, WINRT_WRAP(Windows::Media::Casting::CastingSource));
            *returnValue = detach_from<Windows::Media::Casting::CastingSource>(this->shim().GetAsCastingSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer4> : produce_base<D, Windows::Media::Playback::IMediaPlayer4>
{
    int32_t WINRT_CALL SetSurfaceSize(Windows::Foundation::Size size) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSurfaceSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().SetSurfaceSize(*reinterpret_cast<Windows::Foundation::Size const*>(&size));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSurface(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSurface, WINRT_WRAP(Windows::Media::Playback::MediaPlayerSurface), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::Media::Playback::MediaPlayerSurface>(this->shim().GetSurface(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer5> : produce_base<D, Windows::Media::Playback::IMediaPlayer5>
{
    int32_t WINRT_CALL add_VideoFrameAvailable(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFrameAvailable, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameAvailable(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoFrameAvailable(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoFrameAvailable, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoFrameAvailable(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IsVideoFrameServerEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoFrameServerEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVideoFrameServerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVideoFrameServerEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoFrameServerEnabled, WINRT_WRAP(void), bool);
            this->shim().IsVideoFrameServerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFrameToVideoSurface(void* destination) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFrameToVideoSurface, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            this->shim().CopyFrameToVideoSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFrameToVideoSurfaceWithTargetRectangle(void* destination, Windows::Foundation::Rect targetRectangle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFrameToVideoSurface, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&, Windows::Foundation::Rect const&);
            this->shim().CopyFrameToVideoSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination), *reinterpret_cast<Windows::Foundation::Rect const*>(&targetRectangle));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFrameToStereoscopicVideoSurfaces(void* destinationLeftEye, void* destinationRightEye) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFrameToStereoscopicVideoSurfaces, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&, Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            this->shim().CopyFrameToStereoscopicVideoSurfaces(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destinationLeftEye), *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destinationRightEye));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer6> : produce_base<D, Windows::Media::Playback::IMediaPlayer6>
{
    int32_t WINRT_CALL add_SubtitleFrameChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubtitleFrameChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SubtitleFrameChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Playback::MediaPlayer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SubtitleFrameChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SubtitleFrameChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SubtitleFrameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL RenderSubtitlesToSurface(void* destination, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderSubtitlesToSurface, WINRT_WRAP(bool), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            *result = detach_from<bool>(this->shim().RenderSubtitlesToSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderSubtitlesToSurfaceWithTargetRectangle(void* destination, Windows::Foundation::Rect targetRectangle, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderSubtitlesToSurface, WINRT_WRAP(bool), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&, Windows::Foundation::Rect const&);
            *result = detach_from<bool>(this->shim().RenderSubtitlesToSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&destination), *reinterpret_cast<Windows::Foundation::Rect const*>(&targetRectangle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayer7> : produce_base<D, Windows::Media::Playback::IMediaPlayer7>
{
    int32_t WINRT_CALL get_AudioStateMonitor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioStateMonitor, WINRT_WRAP(Windows::Media::Audio::AudioStateMonitor));
            *value = detach_from<Windows::Media::Audio::AudioStateMonitor>(this->shim().AudioStateMonitor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerEffects> : produce_base<D, Windows::Media::Playback::IMediaPlayerEffects>
{
    int32_t WINRT_CALL AddAudioEffect(void* activatableClassId, bool effectOptional, void* configuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAudioEffect, WINRT_WRAP(void), hstring const&, bool, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().AddAudioEffect(*reinterpret_cast<hstring const*>(&activatableClassId), effectOptional, *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&configuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAllEffects() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAllEffects, WINRT_WRAP(void));
            this->shim().RemoveAllEffects();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerEffects2> : produce_base<D, Windows::Media::Playback::IMediaPlayerEffects2>
{
    int32_t WINRT_CALL AddVideoEffect(void* activatableClassId, bool effectOptional, void* effectConfiguration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddVideoEffect, WINRT_WRAP(void), hstring const&, bool, Windows::Foundation::Collections::IPropertySet const&);
            this->shim().AddVideoEffect(*reinterpret_cast<hstring const*>(&activatableClassId), effectOptional, *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&effectConfiguration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerFailedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlayerFailedEventArgs>
{
    int32_t WINRT_CALL get_Error(Windows::Media::Playback::MediaPlayerError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Media::Playback::MediaPlayerError));
            *value = detach_from<Windows::Media::Playback::MediaPlayerError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> : produce_base<D, Windows::Media::Playback::IMediaPlayerRateChangedEventArgs>
{
    int32_t WINRT_CALL get_NewRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NewRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerSource> : produce_base<D, Windows::Media::Playback::IMediaPlayerSource>
{
    int32_t WINRT_CALL get_ProtectionManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionManager, WINRT_WRAP(Windows::Media::Protection::MediaProtectionManager));
            *value = detach_from<Windows::Media::Protection::MediaProtectionManager>(this->shim().ProtectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtectionManager(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionManager, WINRT_WRAP(void), Windows::Media::Protection::MediaProtectionManager const&);
            this->shim().ProtectionManager(*reinterpret_cast<Windows::Media::Protection::MediaProtectionManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFileSource(void* file) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFileSource, WINRT_WRAP(void), Windows::Storage::IStorageFile const&);
            this->shim().SetFileSource(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStreamSource(void* stream) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStreamSource, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().SetStreamSource(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMediaSource(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMediaSource, WINRT_WRAP(void), Windows::Media::Core::IMediaSource const&);
            this->shim().SetMediaSource(*reinterpret_cast<Windows::Media::Core::IMediaSource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerSource2> : produce_base<D, Windows::Media::Playback::IMediaPlayerSource2>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Media::Playback::IMediaPlaybackSource));
            *value = detach_from<Windows::Media::Playback::IMediaPlaybackSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Media::Playback::IMediaPlaybackSource const&);
            this->shim().Source(*reinterpret_cast<Windows::Media::Playback::IMediaPlaybackSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IMediaPlayerSurface> : produce_base<D, Windows::Media::Playback::IMediaPlayerSurface>
{
    int32_t WINRT_CALL get_CompositionSurface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositionSurface, WINRT_WRAP(Windows::UI::Composition::ICompositionSurface));
            *value = detach_from<Windows::UI::Composition::ICompositionSurface>(this->shim().CompositionSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Compositor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compositor, WINRT_WRAP(Windows::UI::Composition::Compositor));
            *value = detach_from<Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaPlayer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPlayer, WINRT_WRAP(Windows::Media::Playback::MediaPlayer));
            *value = detach_from<Windows::Media::Playback::MediaPlayer>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IPlaybackMediaMarker> : produce_base<D, Windows::Media::Playback::IPlaybackMediaMarker>
{
    int32_t WINRT_CALL get_Time(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Time, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Time());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaMarkerType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaMarkerType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaMarkerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IPlaybackMediaMarkerFactory> : produce_base<D, Windows::Media::Playback::IPlaybackMediaMarkerFactory>
{
    int32_t WINRT_CALL CreateFromTime(Windows::Foundation::TimeSpan value, void** marker) noexcept final
    {
        try
        {
            *marker = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromTime, WINRT_WRAP(Windows::Media::Playback::PlaybackMediaMarker), Windows::Foundation::TimeSpan const&);
            *marker = detach_from<Windows::Media::Playback::PlaybackMediaMarker>(this->shim().CreateFromTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create(Windows::Foundation::TimeSpan value, void* mediaMarketType, void* text, void** marker) noexcept final
    {
        try
        {
            *marker = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Playback::PlaybackMediaMarker), Windows::Foundation::TimeSpan const&, hstring const&, hstring const&);
            *marker = detach_from<Windows::Media::Playback::PlaybackMediaMarker>(this->shim().Create(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value), *reinterpret_cast<hstring const*>(&mediaMarketType), *reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> : produce_base<D, Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs>
{
    int32_t WINRT_CALL get_PlaybackMediaMarker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackMediaMarker, WINRT_WRAP(Windows::Media::Playback::PlaybackMediaMarker));
            *value = detach_from<Windows::Media::Playback::PlaybackMediaMarker>(this->shim().PlaybackMediaMarker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::IPlaybackMediaMarkerSequence> : produce_base<D, Windows::Media::Playback::IPlaybackMediaMarkerSequence>
{
    int32_t WINRT_CALL get_Size(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Insert(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Insert, WINRT_WRAP(void), Windows::Media::Playback::PlaybackMediaMarker const&);
            this->shim().Insert(*reinterpret_cast<Windows::Media::Playback::PlaybackMediaMarker const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> : produce_base<D, Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs>
{
    int32_t WINRT_CALL get_Track(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Track, WINRT_WRAP(Windows::Media::Core::TimedMetadataTrack));
            *value = detach_from<Windows::Media::Core::TimedMetadataTrack>(this->shim().Track());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldPresentationMode(Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldPresentationMode, WINRT_WRAP(Windows::Media::Playback::TimedMetadataTrackPresentationMode));
            *value = detach_from<Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().OldPresentationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewPresentationMode(Windows::Media::Playback::TimedMetadataTrackPresentationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewPresentationMode, WINRT_WRAP(Windows::Media::Playback::TimedMetadataTrackPresentationMode));
            *value = detach_from<Windows::Media::Playback::TimedMetadataTrackPresentationMode>(this->shim().NewPresentationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Playback {

inline Windows::Media::Playback::MediaPlayer BackgroundMediaPlayer::Current()
{
    return impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.Current(); });
}

inline winrt::event_token BackgroundMediaPlayer::MessageReceivedFromBackground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
{
    return impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.MessageReceivedFromBackground(value); });
}

inline BackgroundMediaPlayer::MessageReceivedFromBackground_revoker BackgroundMediaPlayer::MessageReceivedFromBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
{
    auto f = get_activation_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>();
    return { f, f.MessageReceivedFromBackground(value) };
}

inline void BackgroundMediaPlayer::MessageReceivedFromBackground(winrt::event_token const& token)
{
    impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.MessageReceivedFromBackground(token); });
}

inline winrt::event_token BackgroundMediaPlayer::MessageReceivedFromForeground(Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
{
    return impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.MessageReceivedFromForeground(value); });
}

inline BackgroundMediaPlayer::MessageReceivedFromForeground_revoker BackgroundMediaPlayer::MessageReceivedFromForeground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> const& value)
{
    auto f = get_activation_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>();
    return { f, f.MessageReceivedFromForeground(value) };
}

inline void BackgroundMediaPlayer::MessageReceivedFromForeground(winrt::event_token const& token)
{
    impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.MessageReceivedFromForeground(token); });
}

inline void BackgroundMediaPlayer::SendMessageToBackground(Windows::Foundation::Collections::ValueSet const& value)
{
    impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.SendMessageToBackground(value); });
}

inline void BackgroundMediaPlayer::SendMessageToForeground(Windows::Foundation::Collections::ValueSet const& value)
{
    impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.SendMessageToForeground(value); });
}

inline bool BackgroundMediaPlayer::IsMediaPlaying()
{
    return impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.IsMediaPlaying(); });
}

inline void BackgroundMediaPlayer::Shutdown()
{
    impl::call_factory<BackgroundMediaPlayer, Windows::Media::Playback::IBackgroundMediaPlayerStatics>([&](auto&& f) { return f.Shutdown(); });
}

inline MediaBreak::MediaBreak(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod) :
    MediaBreak(impl::call_factory<MediaBreak, Windows::Media::Playback::IMediaBreakFactory>([&](auto&& f) { return f.Create(insertionMethod); }))
{}

inline MediaBreak::MediaBreak(Windows::Media::Playback::MediaBreakInsertionMethod const& insertionMethod, Windows::Foundation::TimeSpan const& presentationPosition) :
    MediaBreak(impl::call_factory<MediaBreak, Windows::Media::Playback::IMediaBreakFactory>([&](auto&& f) { return f.CreateWithPresentationPosition(insertionMethod, presentationPosition); }))
{}

inline MediaPlaybackItem::MediaPlaybackItem(Windows::Media::Core::MediaSource const& source) :
    MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, Windows::Media::Playback::IMediaPlaybackItemFactory>([&](auto&& f) { return f.Create(source); }))
{}

inline MediaPlaybackItem::MediaPlaybackItem(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime) :
    MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, Windows::Media::Playback::IMediaPlaybackItemFactory2>([&](auto&& f) { return f.CreateWithStartTime(source, startTime); }))
{}

inline MediaPlaybackItem::MediaPlaybackItem(Windows::Media::Core::MediaSource const& source, Windows::Foundation::TimeSpan const& startTime, Windows::Foundation::TimeSpan const& durationLimit) :
    MediaPlaybackItem(impl::call_factory<MediaPlaybackItem, Windows::Media::Playback::IMediaPlaybackItemFactory2>([&](auto&& f) { return f.CreateWithStartTimeAndDurationLimit(source, startTime, durationLimit); }))
{}

inline Windows::Media::Playback::MediaPlaybackItem MediaPlaybackItem::FindFromMediaSource(Windows::Media::Core::MediaSource const& source)
{
    return impl::call_factory<MediaPlaybackItem, Windows::Media::Playback::IMediaPlaybackItemStatics>([&](auto&& f) { return f.FindFromMediaSource(source); });
}

inline MediaPlaybackList::MediaPlaybackList() :
    MediaPlaybackList(impl::call_factory<MediaPlaybackList>([](auto&& f) { return f.template ActivateInstance<MediaPlaybackList>(); }))
{}

inline MediaPlayer::MediaPlayer() :
    MediaPlayer(impl::call_factory<MediaPlayer>([](auto&& f) { return f.template ActivateInstance<MediaPlayer>(); }))
{}

inline PlaybackMediaMarker::PlaybackMediaMarker(Windows::Foundation::TimeSpan const& value) :
    PlaybackMediaMarker(impl::call_factory<PlaybackMediaMarker, Windows::Media::Playback::IPlaybackMediaMarkerFactory>([&](auto&& f) { return f.CreateFromTime(value); }))
{}

inline PlaybackMediaMarker::PlaybackMediaMarker(Windows::Foundation::TimeSpan const& value, param::hstring const& mediaMarketType, param::hstring const& text) :
    PlaybackMediaMarker(impl::call_factory<PlaybackMediaMarker, Windows::Media::Playback::IPlaybackMediaMarkerFactory>([&](auto&& f) { return f.Create(value, mediaMarketType, text); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IBackgroundMediaPlayerStatics> {};
template<> struct hash<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::ICurrentMediaPlaybackItemChangedEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreak> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreak> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakEndedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakFactory> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakFactory> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakManager> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakManager> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSchedule> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakSchedule> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakSeekedOverEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakSkippedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaBreakStartedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaEnginePlaybackSource> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaEnginePlaybackSource> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaItemDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaItemDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManager> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManager> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerCommandBehavior> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerFastForwardReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerNextReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPauseReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPlayReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPositionReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerPreviousReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRateReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerRewindReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackCommandManagerShuffleReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItem> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItem2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItem3> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItem3> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemError> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemError> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemFactory2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemOpenedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackItemStatics> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackItemStatics> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackList> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackList2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackList3> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackList3> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSession> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSession2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSession3> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSession3> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSessionBufferingStartedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSessionOutputDegradationPolicyState> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSource> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSource> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackSphericalVideoProjection> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlaybackTimedMetadataTrackList> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer3> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer3> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer4> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer4> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer5> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer5> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer6> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer6> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayer7> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayer7> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerEffects> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerEffects> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerEffects2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerEffects2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerRateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSource> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerSource> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSource2> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerSource2> {};
template<> struct hash<winrt::Windows::Media::Playback::IMediaPlayerSurface> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IMediaPlayerSurface> {};
template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarker> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IPlaybackMediaMarker> {};
template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IPlaybackMediaMarkerFactory> {};
template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IPlaybackMediaMarkerReachedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence> : winrt::impl::hash_base<winrt::Windows::Media::Playback::IPlaybackMediaMarkerSequence> {};
template<> struct hash<winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::ITimedMetadataPresentationModeChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::BackgroundMediaPlayer> : winrt::impl::hash_base<winrt::Windows::Media::Playback::BackgroundMediaPlayer> {};
template<> struct hash<winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::CurrentMediaPlaybackItemChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreak> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreak> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakEndedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakManager> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakManager> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSchedule> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakSchedule> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakSeekedOverEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakSkippedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaBreakStartedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaItemDisplayProperties> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaItemDisplayProperties> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackAudioTrackList> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManager> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManager> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerAutoRepeatModeReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerCommandBehavior> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerFastForwardReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerNextReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPauseReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPlayReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPositionReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerPreviousReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRateReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerRewindReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackCommandManagerShuffleReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItem> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackItem> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemError> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackItemError> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackItemFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackItemOpenedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackList> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSession> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackSession> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackSessionBufferingStartedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackSessionOutputDegradationPolicyState> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackSphericalVideoProjection> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackTimedMetadataTrackList> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlaybackVideoTrackList> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlayer> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlayer> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlayerDataReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlayerFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlayerRateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::MediaPlayerSurface> : winrt::impl::hash_base<winrt::Windows::Media::Playback::MediaPlayerSurface> {};
template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarker> : winrt::impl::hash_base<winrt::Windows::Media::Playback::PlaybackMediaMarker> {};
template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::PlaybackMediaMarkerReachedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence> : winrt::impl::hash_base<winrt::Windows::Media::Playback::PlaybackMediaMarkerSequence> {};
template<> struct hash<winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Playback::TimedMetadataPresentationModeChangedEventArgs> {};

}
