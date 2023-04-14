// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.PlayTo.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_PlayTo_ICurrentTimeChangeRequestedEventArgs<D>::Time() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs)->get_Time(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_PlayTo_IMuteChangeRequestedEventArgs<D>::Mute() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IMuteChangeRequestedEventArgs)->get_Mute(&value));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToConnectionState consume_Windows_Media_PlayTo_IPlayToConnection<D>::State() const
{
    Windows::Media::PlayTo::PlayToConnectionState value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToConnection<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->remove_StateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->add_Transferred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Transferred_revoker>(this, Transferred(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToConnection<D>::Transferred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->remove_Transferred(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->add_Error(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error_revoker consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Error_revoker>(this, Error(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToConnection<D>::Error(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnection)->remove_Error(get_abi(token)));
}

template <typename D> Windows::Media::PlayTo::PlayToConnectionError consume_Windows_Media_PlayTo_IPlayToConnectionErrorEventArgs<D>::Code() const
{
    Windows::Media::PlayTo::PlayToConnectionError value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs)->get_Code(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_IPlayToConnectionErrorEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToConnectionState consume_Windows_Media_PlayTo_IPlayToConnectionStateChangedEventArgs<D>::PreviousState() const
{
    Windows::Media::PlayTo::PlayToConnectionState value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs)->get_PreviousState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToConnectionState consume_Windows_Media_PlayTo_IPlayToConnectionStateChangedEventArgs<D>::CurrentState() const
{
    Windows::Media::PlayTo::PlayToConnectionState value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs)->get_CurrentState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToSource consume_Windows_Media_PlayTo_IPlayToConnectionTransferredEventArgs<D>::PreviousSource() const
{
    Windows::Media::PlayTo::PlayToSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs)->get_PreviousSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToSource consume_Windows_Media_PlayTo_IPlayToConnectionTransferredEventArgs<D>::CurrentSource() const
{
    Windows::Media::PlayTo::PlayToSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs)->get_CurrentSource(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->add_SourceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested_revoker consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceRequested_revoker>(this, SourceRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->remove_SourceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->add_SourceSelected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected_revoker consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceSelected_revoker>(this, SourceSelected(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToManager<D>::SourceSelected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->remove_SourceSelected(get_abi(token)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToManager<D>::DefaultSourceSelection(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->put_DefaultSourceSelection(value));
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToManager<D>::DefaultSourceSelection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManager)->get_DefaultSourceSelection(&value));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToManager consume_Windows_Media_PlayTo_IPlayToManagerStatics<D>::GetForCurrentView() const
{
    Windows::Media::PlayTo::PlayToManager playToManager{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManagerStatics)->GetForCurrentView(put_abi(playToManager)));
    return playToManager;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToManagerStatics<D>::ShowPlayToUI() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToManagerStatics)->ShowPlayToUI());
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_PlayRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PlayRequested_revoker>(this, PlayRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlayRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_PlayRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_PauseRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PauseRequested_revoker>(this, PauseRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PauseRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_PauseRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_SourceChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceChangeRequested_revoker>(this, SourceChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SourceChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_SourceChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_PlaybackRateChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlaybackRateChangeRequested_revoker>(this, PlaybackRateChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::PlaybackRateChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_PlaybackRateChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_CurrentTimeChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CurrentTimeChangeRequested_revoker>(this, CurrentTimeChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::CurrentTimeChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_CurrentTimeChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_MuteChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MuteChangeRequested_revoker>(this, MuteChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::MuteChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_MuteChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_VolumeChangeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VolumeChangeRequested_revoker>(this, VolumeChangeRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::VolumeChangeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_VolumeChangeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_TimeUpdateRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, TimeUpdateRequested_revoker>(this, TimeUpdateRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::TimeUpdateRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_TimeUpdateRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->add_StopRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested_revoker consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StopRequested_revoker>(this, StopRequested(handler));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->remove_StopRequested(get_abi(token)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyVolumeChange(double volume, bool mute) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyVolumeChange(volume, mute));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyRateChange(double rate) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyRateChange(rate));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyLoadedMetadata() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyLoadedMetadata());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyTimeUpdate(Windows::Foundation::TimeSpan const& currentTime) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyTimeUpdate(get_abi(currentTime)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyDurationChange(Windows::Foundation::TimeSpan const& duration) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyDurationChange(get_abi(duration)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifySeeking() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifySeeking());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifySeeked() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifySeeked());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyPaused() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyPaused());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyPlaying() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyPlaying());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyEnded() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyEnded());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyError() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyError());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::NotifyStopped() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->NotifyStopped());
}

template <typename D> hstring consume_Windows_Media_PlayTo_IPlayToReceiver<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::FriendlyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->put_FriendlyName(get_abi(value)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsImage(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsImage(value));
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsImage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsImage(&value));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsAudio(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsAudio(value));
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsAudio() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsAudio(&value));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsVideo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->put_SupportsVideo(value));
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToReceiver<D>::SupportsVideo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->get_SupportsVideo(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Media_PlayTo_IPlayToReceiver<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->StartAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_PlayTo_IPlayToReceiver<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToReceiver)->StopAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Media::PlayTo::PlayToConnection consume_Windows_Media_PlayTo_IPlayToSource<D>::Connection() const
{
    Windows::Media::PlayTo::PlayToConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSource)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::PlayTo::PlayToSource consume_Windows_Media_PlayTo_IPlayToSource<D>::Next() const
{
    Windows::Media::PlayTo::PlayToSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSource)->get_Next(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSource<D>::Next(Windows::Media::PlayTo::PlayToSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSource)->put_Next(get_abi(value)));
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSource<D>::PlayNext() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSource)->PlayNext());
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSourceDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceDeferral)->Complete());
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::DisplayErrorString(param::hstring const& errorString) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceRequest)->DisplayErrorString(get_abi(errorString)));
}

template <typename D> Windows::Media::PlayTo::PlayToSourceDeferral consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::GetDeferral() const
{
    Windows::Media::PlayTo::PlayToSourceDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSourceRequest<D>::SetSource(Windows::Media::PlayTo::PlayToSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceRequest)->SetSource(get_abi(value)));
}

template <typename D> Windows::Media::PlayTo::PlayToSourceRequest consume_Windows_Media_PlayTo_IPlayToSourceRequestedEventArgs<D>::SourceRequest() const
{
    Windows::Media::PlayTo::PlayToSourceRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs)->get_SourceRequest(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::Icon() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsImage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsImage(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsAudio() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsAudio(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_PlayTo_IPlayToSourceSelectedEventArgs<D>::SupportsVideo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs)->get_SupportsVideo(&value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_PlayTo_IPlayToSourceWithPreferredSourceUri<D>::PreferredSourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri)->get_PreferredSourceUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_PlayTo_IPlayToSourceWithPreferredSourceUri<D>::PreferredSourceUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri)->put_PreferredSourceUri(get_abi(value)));
}

template <typename D> double consume_Windows_Media_PlayTo_IPlaybackRateChangeRequestedEventArgs<D>::Rate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs)->get_Rate(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Stream() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Stream(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Author() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Author(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Album() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Album(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Genre() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Genre(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Date() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Date(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Rating() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Rating(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Media_PlayTo_ISourceChangeRequestedEventArgs<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::ISourceChangeRequestedEventArgs)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_PlayTo_IVolumeChangeRequestedEventArgs<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs)->get_Volume(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs>
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
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IMuteChangeRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::IMuteChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_Mute(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mute, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Mute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToConnection> : produce_base<D, Windows::Media::PlayTo::IPlayToConnection>
{
    int32_t WINRT_CALL get_State(Windows::Media::PlayTo::PlayToConnectionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::PlayTo::PlayToConnectionState));
            *value = detach_from<Windows::Media::PlayTo::PlayToConnectionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Transferred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transferred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Transferred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Transferred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Transferred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Transferred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Error(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Error(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToConnection, Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Error(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Error(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs>
{
    int32_t WINRT_CALL get_Code(Windows::Media::PlayTo::PlayToConnectionError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code, WINRT_WRAP(Windows::Media::PlayTo::PlayToConnectionError));
            *value = detach_from<Windows::Media::PlayTo::PlayToConnectionError>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs>
{
    int32_t WINRT_CALL get_PreviousState(Windows::Media::PlayTo::PlayToConnectionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousState, WINRT_WRAP(Windows::Media::PlayTo::PlayToConnectionState));
            *value = detach_from<Windows::Media::PlayTo::PlayToConnectionState>(this->shim().PreviousState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentState(Windows::Media::PlayTo::PlayToConnectionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentState, WINRT_WRAP(Windows::Media::PlayTo::PlayToConnectionState));
            *value = detach_from<Windows::Media::PlayTo::PlayToConnectionState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs>
{
    int32_t WINRT_CALL get_PreviousSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousSource, WINRT_WRAP(Windows::Media::PlayTo::PlayToSource));
            *value = detach_from<Windows::Media::PlayTo::PlayToSource>(this->shim().PreviousSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentSource, WINRT_WRAP(Windows::Media::PlayTo::PlayToSource));
            *value = detach_from<Windows::Media::PlayTo::PlayToSource>(this->shim().CurrentSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToManager> : produce_base<D, Windows::Media::PlayTo::IPlayToManager>
{
    int32_t WINRT_CALL add_SourceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceSelected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceSelected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceSelected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToManager, Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceSelected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceSelected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceSelected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL put_DefaultSourceSelection(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultSourceSelection, WINRT_WRAP(void), bool);
            this->shim().DefaultSourceSelection(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultSourceSelection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultSourceSelection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DefaultSourceSelection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToManagerStatics> : produce_base<D, Windows::Media::PlayTo::IPlayToManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** playToManager) noexcept final
    {
        try
        {
            *playToManager = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Media::PlayTo::PlayToManager));
            *playToManager = detach_from<Windows::Media::PlayTo::PlayToManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowPlayToUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowPlayToUI, WINRT_WRAP(void));
            this->shim().ShowPlayToUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToReceiver> : produce_base<D, Windows::Media::PlayTo::IPlayToReceiver>
{
    int32_t WINRT_CALL add_PlayRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlayRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlayRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlayRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PauseRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PauseRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PauseRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PauseRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PauseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::SourceChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackRateChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRateChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackRateChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackRateChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackRateChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackRateChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CurrentTimeChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentTimeChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentTimeChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentTimeChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentTimeChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentTimeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MuteChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MuteChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MuteChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::MuteChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MuteChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MuteChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MuteChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VolumeChangeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VolumeChangeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VolumeChangeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VolumeChangeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VolumeChangeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VolumeChangeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TimeUpdateRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeUpdateRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().TimeUpdateRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TimeUpdateRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TimeUpdateRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TimeUpdateRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StopRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StopRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::PlayTo::PlayToReceiver, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StopRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StopRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StopRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NotifyVolumeChange(double volume, bool mute) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyVolumeChange, WINRT_WRAP(void), double, bool);
            this->shim().NotifyVolumeChange(volume, mute);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyRateChange(double rate) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyRateChange, WINRT_WRAP(void), double);
            this->shim().NotifyRateChange(rate);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyLoadedMetadata() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyLoadedMetadata, WINRT_WRAP(void));
            this->shim().NotifyLoadedMetadata();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyTimeUpdate(Windows::Foundation::TimeSpan currentTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyTimeUpdate, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().NotifyTimeUpdate(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&currentTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyDurationChange(Windows::Foundation::TimeSpan duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyDurationChange, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().NotifyDurationChange(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifySeeking() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifySeeking, WINRT_WRAP(void));
            this->shim().NotifySeeking();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifySeeked() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifySeeked, WINRT_WRAP(void));
            this->shim().NotifySeeked();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyPaused() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyPaused, WINRT_WRAP(void));
            this->shim().NotifyPaused();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyPlaying() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyPlaying, WINRT_WRAP(void));
            this->shim().NotifyPlaying();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyEnded() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyEnded, WINRT_WRAP(void));
            this->shim().NotifyEnded();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyError() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyError, WINRT_WRAP(void));
            this->shim().NotifyError();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyStopped() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyStopped, WINRT_WRAP(void));
            this->shim().NotifyStopped();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FriendlyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(void), hstring const&);
            this->shim().FriendlyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsImage(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsImage, WINRT_WRAP(void), bool);
            this->shim().SupportsImage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsImage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsImage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsAudio(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAudio, WINRT_WRAP(void), bool);
            this->shim().SupportsAudio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsAudio(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAudio, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SupportsVideo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVideo, WINRT_WRAP(void), bool);
            this->shim().SupportsVideo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsVideo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVideo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSource> : produce_base<D, Windows::Media::PlayTo::IPlayToSource>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Media::PlayTo::PlayToConnection));
            *value = detach_from<Windows::Media::PlayTo::PlayToConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Next(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Next, WINRT_WRAP(Windows::Media::PlayTo::PlayToSource));
            *value = detach_from<Windows::Media::PlayTo::PlayToSource>(this->shim().Next());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Next(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Next, WINRT_WRAP(void), Windows::Media::PlayTo::PlayToSource const&);
            this->shim().Next(*reinterpret_cast<Windows::Media::PlayTo::PlayToSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PlayNext() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayNext, WINRT_WRAP(void));
            this->shim().PlayNext();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSourceDeferral> : produce_base<D, Windows::Media::PlayTo::IPlayToSourceDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSourceRequest> : produce_base<D, Windows::Media::PlayTo::IPlayToSourceRequest>
{
    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisplayErrorString(void* errorString) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayErrorString, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayErrorString(*reinterpret_cast<hstring const*>(&errorString));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Media::PlayTo::PlayToSourceDeferral));
            *deferral = detach_from<Windows::Media::PlayTo::PlayToSourceDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSource, WINRT_WRAP(void), Windows::Media::PlayTo::PlayToSource const&);
            this->shim().SetSource(*reinterpret_cast<Windows::Media::PlayTo::PlayToSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs>
{
    int32_t WINRT_CALL get_SourceRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceRequest, WINRT_WRAP(Windows::Media::PlayTo::PlayToSourceRequest));
            *value = detach_from<Windows::Media::PlayTo::PlayToSourceRequest>(this->shim().SourceRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs>
{
    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsImage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsImage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsAudio(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAudio, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsVideo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVideo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri> : produce_base<D, Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri>
{
    int32_t WINRT_CALL get_PreferredSourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredSourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().PreferredSourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredSourceUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredSourceUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().PreferredSourceUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_Rate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Rate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::ISourceChangeRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::ISourceChangeRequestedEventArgs>
{
    int32_t WINRT_CALL get_Stream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().Stream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Album(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Album, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Album());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Genre(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Genre, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Genre());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Date());
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

    int32_t WINRT_CALL get_Rating(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs> : produce_base<D, Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs>
{
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
};

}

WINRT_EXPORT namespace winrt::Windows::Media::PlayTo {

inline Windows::Media::PlayTo::PlayToManager PlayToManager::GetForCurrentView()
{
    return impl::call_factory<PlayToManager, Windows::Media::PlayTo::IPlayToManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline void PlayToManager::ShowPlayToUI()
{
    impl::call_factory<PlayToManager, Windows::Media::PlayTo::IPlayToManagerStatics>([&](auto&& f) { return f.ShowPlayToUI(); });
}

inline PlayToReceiver::PlayToReceiver() :
    PlayToReceiver(impl::call_factory<PlayToReceiver>([](auto&& f) { return f.template ActivateInstance<PlayToReceiver>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IMuteChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnection> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToConnection> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToManager> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToManager> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToManagerStatics> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToReceiver> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToReceiver> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSource> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSource> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceDeferral> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSourceDeferral> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceRequest> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSourceRequest> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::ISourceChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::CurrentTimeChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::MuteChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnection> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToConnection> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToConnectionErrorEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToConnectionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToConnectionTransferredEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToManager> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToManager> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToReceiver> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToReceiver> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSource> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToSource> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceDeferral> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToSourceDeferral> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceRequest> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToSourceRequest> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToSourceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlayToSourceSelectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::PlaybackRateChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::SourceChangeRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::PlayTo::VolumeChangeRequestedEventArgs> {};

}
