// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Streaming.Adaptive.2.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::IsLive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_IsLive(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredLiveOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_DesiredLiveOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredLiveOffset(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->put_DesiredLiveOffset(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::InitialBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_InitialBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::InitialBitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->put_InitialBitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::CurrentDownloadBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_CurrentDownloadBitrate(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::CurrentPlaybackBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_CurrentPlaybackBitrate(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::AvailableBitrates() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_AvailableBitrates(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredMinBitrate() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_DesiredMinBitrate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredMinBitrate(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->put_DesiredMinBitrate(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredMaxBitrate() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_DesiredMaxBitrate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DesiredMaxBitrate(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->put_DesiredMaxBitrate(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::AudioOnlyPlayback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_AudioOnlyPlayback(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::InboundBitsPerSecond() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_InboundBitsPerSecond(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::InboundBitsPerSecondWindow() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->get_InboundBitsPerSecondWindow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->put_InboundBitsPerSecondWindow(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadBitrateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->add_DownloadBitrateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadBitrateChanged_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadBitrateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadBitrateChanged_revoker>(this, DownloadBitrateChanged(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadBitrateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->remove_DownloadBitrateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::PlaybackBitrateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->add_PlaybackBitrateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::PlaybackBitrateChanged_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::PlaybackBitrateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlaybackBitrateChanged_revoker>(this, PlaybackBitrateChanged(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::PlaybackBitrateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->remove_PlaybackBitrateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->add_DownloadRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadRequested_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadRequested_revoker>(this, DownloadRequested(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->remove_DownloadRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->add_DownloadCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadCompleted_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadCompleted_revoker>(this, DownloadCompleted(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->remove_DownloadCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->add_DownloadFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadFailed_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadFailed_revoker>(this, DownloadFailed(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource<D>::DownloadFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource)->remove_DownloadFailed(get_abi(token)));
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource2<D>::AdvancedSettings() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2)->get_AdvancedSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::MinLiveOffset() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->get_MinLiveOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::MaxSeekableWindowSize() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->get_MaxSeekableWindowSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::DesiredSeekableWindowSize() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->get_DesiredSeekableWindowSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::DesiredSeekableWindowSize(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->put_DesiredSeekableWindowSize(get_abi(value)));
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::Diagnostics() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->get_Diagnostics(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSource3<D>::GetCorrelatedTimes() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3)->GetCorrelatedTimes(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::AllSegmentsIndependent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->get_AllSegmentsIndependent(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::AllSegmentsIndependent(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->put_AllSegmentsIndependent(value));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::DesiredBitrateHeadroomRatio() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->get_DesiredBitrateHeadroomRatio(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::DesiredBitrateHeadroomRatio(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->put_DesiredBitrateHeadroomRatio(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::BitrateDowngradeTriggerRatio() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->get_BitrateDowngradeTriggerRatio(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceAdvancedSettings<D>::BitrateDowngradeTriggerRatio(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings)->put_BitrateDowngradeTriggerRatio(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCorrelatedTimes<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCorrelatedTimes<D>::PresentationTimeStamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes)->get_PresentationTimeStamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCorrelatedTimes<D>::ProgramDateTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes)->get_ProgramDateTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult<D>::Status() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSource consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult<D>::MediaSource() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult)->get_MediaSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult<D>::HttpResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult)->get_HttpResponseMessage(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceCreationResult2<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::DiagnosticType() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_DiagnosticType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::RequestId() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_RequestId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::SegmentId() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_SegmentId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::ResourceType() const
{
    Windows::Foundation::IReference<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_ResourceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::ResourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_ResourceUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::ResourceByteRangeOffset() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_ResourceByteRangeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::ResourceByteRangeLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_ResourceByteRangeLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs<D>::Bitrate() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs)->get_Bitrate(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs2<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs3<D>::ResourceDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3)->get_ResourceDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnosticAvailableEventArgs3<D>::ResourceContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3)->get_ResourceContentType(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics<D>::DiagnosticAvailable(Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics)->add_DiagnosticAvailable(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics<D>::DiagnosticAvailable_revoker consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics<D>::DiagnosticAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DiagnosticAvailable_revoker>(this, DiagnosticAvailable(handler));
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDiagnostics<D>::DiagnosticAvailable(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics)->remove_DiagnosticAvailable(get_abi(token)));
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs<D>::OldValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs)->get_OldValue(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs<D>::NewValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs)->get_NewValue(&value));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2<D>::Reason() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>::ResourceType() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs)->get_ResourceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>::ResourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs)->get_ResourceUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>::ResourceByteRangeOffset() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs)->get_ResourceByteRangeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>::ResourceByteRangeLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs)->get_ResourceByteRangeLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs<D>::HttpResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs)->get_HttpResponseMessage(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs2<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2)->get_RequestId(&value));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs2<D>::Statistics() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2)->get_Statistics(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs2<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs3<D>::ResourceDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3)->get_ResourceDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadCompletedEventArgs3<D>::ResourceContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3)->get_ResourceContentType(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>::ResourceType() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs)->get_ResourceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>::ResourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs)->get_ResourceUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>::ResourceByteRangeOffset() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs)->get_ResourceByteRangeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>::ResourceByteRangeLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs)->get_ResourceByteRangeLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs<D>::HttpResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs)->get_HttpResponseMessage(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2)->get_RequestId(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2<D>::Statistics() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2)->get_Statistics(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs2<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs3<D>::ResourceDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3)->get_ResourceDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadFailedEventArgs3<D>::ResourceContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3)->get_ResourceContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral)->Complete());
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::ResourceType() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->get_ResourceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::ResourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->get_ResourceUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::ResourceByteRangeOffset() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->get_ResourceByteRangeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::ResourceByteRangeLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->get_ResourceByteRangeLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::Result() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->get_Result(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> int32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs2<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2)->get_RequestId(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs2<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs3<D>::ResourceDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3)->get_ResourceDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadRequestedEventArgs3<D>::ResourceContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3)->get_ResourceContentType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ResourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->get_ResourceUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ResourceUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->put_ResourceUri(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::InputStream(Windows::Storage::Streams::IInputStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->put_InputStream(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::Buffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->get_Buffer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::Buffer(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->put_Buffer(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ContentType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->put_ContentType(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ExtendedStatus() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->get_ExtendedStatus(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult<D>::ExtendedStatus(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult)->put_ExtendedStatus(value));
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2<D>::ResourceByteRangeOffset() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2)->get_ResourceByteRangeOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2<D>::ResourceByteRangeOffset(optional<uint64_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2)->put_ResourceByteRangeOffset(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2<D>::ResourceByteRangeLength() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2)->get_ResourceByteRangeLength(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadResult2<D>::ResourceByteRangeLength(optional<uint64_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2)->put_ResourceByteRangeLength(get_abi(value)));
}

template <typename D> uint64_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics<D>::ContentBytesReceivedCount() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics)->get_ContentBytesReceivedCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics<D>::TimeToHeadersReceived() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics)->get_TimeToHeadersReceived(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics<D>::TimeToFirstByteReceived() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics)->get_TimeToFirstByteReceived(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceDownloadStatistics<D>::TimeToLastByteReceived() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics)->get_TimeToLastByteReceived(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs<D>::OldValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs)->get_OldValue(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs<D>::NewValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs)->get_NewValue(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs<D>::AudioOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs)->get_AudioOnly(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>::IsContentTypeSupported(param::hstring const& contentType) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics)->IsContentTypeSupported(get_abi(contentType), &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>::CreateFromUriAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics)->CreateFromUriAsync(get_abi(uri), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>::CreateFromUriAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpClient const& httpClient) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics)->CreateFromUriWithDownloaderAsync(get_abi(uri), get_abi(httpClient), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics)->CreateFromStreamAsync(get_abi(stream), get_abi(uri), get_abi(contentType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> consume_Windows_Media_Streaming_Adaptive_IAdaptiveMediaSourceStatics<D>::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType, Windows::Web::Http::HttpClient const& httpClient) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics)->CreateFromStreamWithDownloaderAsync(get_abi(stream), get_abi(uri), get_abi(contentType), get_abi(httpClient), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource>
{
    int32_t WINRT_CALL get_IsLive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredLiveOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredLiveOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DesiredLiveOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredLiveOffset(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredLiveOffset, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DesiredLiveOffset(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().InitialBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialBitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialBitrate, WINRT_WRAP(void), uint32_t);
            this->shim().InitialBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentDownloadBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentDownloadBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CurrentDownloadBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentPlaybackBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPlaybackBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CurrentPlaybackBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AvailableBitrates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableBitrates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().AvailableBitrates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredMinBitrate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMinBitrate, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().DesiredMinBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredMinBitrate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMinBitrate, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().DesiredMinBitrate(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredMaxBitrate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMaxBitrate, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().DesiredMaxBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredMaxBitrate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMaxBitrate, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().DesiredMaxBitrate(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioOnlyPlayback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioOnlyPlayback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AudioOnlyPlayback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InboundBitsPerSecond(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBitsPerSecond, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().InboundBitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBitsPerSecondWindow, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().InboundBitsPerSecondWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InboundBitsPerSecondWindow(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBitsPerSecondWindow, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().InboundBitsPerSecondWindow(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DownloadBitrateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadBitrateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadBitrateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadBitrateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadBitrateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadBitrateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlaybackBitrateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackBitrateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlaybackBitrateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlaybackBitrateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlaybackBitrateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlaybackBitrateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2>
{
    int32_t WINRT_CALL get_AdvancedSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvancedSettings, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings>(this->shim().AdvancedSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3>
{
    int32_t WINRT_CALL get_MinLiveOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinLiveOffset, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MinLiveOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSeekableWindowSize(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSeekableWindowSize, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().MaxSeekableWindowSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredSeekableWindowSize(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredSeekableWindowSize, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().DesiredSeekableWindowSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredSeekableWindowSize(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredSeekableWindowSize, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().DesiredSeekableWindowSize(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Diagnostics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Diagnostics, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics>(this->shim().Diagnostics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCorrelatedTimes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCorrelatedTimes, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes>(this->shim().GetCorrelatedTimes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings>
{
    int32_t WINRT_CALL get_AllSegmentsIndependent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllSegmentsIndependent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllSegmentsIndependent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllSegmentsIndependent(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllSegmentsIndependent, WINRT_WRAP(void), bool);
            this->shim().AllSegmentsIndependent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredBitrateHeadroomRatio(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredBitrateHeadroomRatio, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().DesiredBitrateHeadroomRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredBitrateHeadroomRatio(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredBitrateHeadroomRatio, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().DesiredBitrateHeadroomRatio(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitrateDowngradeTriggerRatio(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitrateDowngradeTriggerRatio, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().BitrateDowngradeTriggerRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BitrateDowngradeTriggerRatio(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitrateDowngradeTriggerRatio, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().BitrateDowngradeTriggerRatio(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes>
{
    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationTimeStamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationTimeStamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().PresentationTimeStamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProgramDateTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgramDateTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ProgramDateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaSource, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSource));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>(this->shim().MediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().HttpResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2>
{
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
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs>
{
    int32_t WINRT_CALL get_DiagnosticType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiagnosticType, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticType>(this->shim().DiagnosticType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SegmentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SegmentId, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().SegmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceType, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>>(this->shim().ResourceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ResourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2>
{
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
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3>
{
    int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().ResourceDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResourceContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics>
{
    int32_t WINRT_CALL add_DiagnosticAvailable(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiagnosticAvailable, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DiagnosticAvailable(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics, Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DiagnosticAvailable(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DiagnosticAvailable, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DiagnosticAvailable(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs>
{
    int32_t WINRT_CALL get_OldValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2>
{
    int32_t WINRT_CALL get_Reason(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs>
{
    int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceType, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>(this->shim().ResourceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ResourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().HttpResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Statistics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Statistics, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics>(this->shim().Statistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3>
{
    int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().ResourceDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResourceContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs>
{
    int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceType, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>(this->shim().ResourceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ResourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HttpResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().HttpResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
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

    int32_t WINRT_CALL get_Statistics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Statistics, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics>(this->shim().Statistics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3>
{
    int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().ResourceDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResourceContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral>
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
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs>
{
    int32_t WINRT_CALL get_ResourceType(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceType, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceResourceType>(this->shim().ResourceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ResourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult>(this->shim().Result());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral));
            *deferral = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3>
{
    int32_t WINRT_CALL get_ResourceDuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().ResourceDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResourceContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult>
{
    int32_t WINRT_CALL get_ResourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ResourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ResourceUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().ResourceUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InputStream(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(void), Windows::Storage::Streams::IInputStream const&);
            this->shim().InputStream(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Buffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Buffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Buffer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Buffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(void), hstring const&);
            this->shim().ContentType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExtendedStatus(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(void), uint32_t);
            this->shim().ExtendedStatus(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2>
{
    int32_t WINRT_CALL get_ResourceByteRangeOffset(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ResourceByteRangeOffset(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeOffset, WINRT_WRAP(void), Windows::Foundation::IReference<uint64_t> const&);
            this->shim().ResourceByteRangeOffset(*reinterpret_cast<Windows::Foundation::IReference<uint64_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResourceByteRangeLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().ResourceByteRangeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ResourceByteRangeLength(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResourceByteRangeLength, WINRT_WRAP(void), Windows::Foundation::IReference<uint64_t> const&);
            this->shim().ResourceByteRangeLength(*reinterpret_cast<Windows::Foundation::IReference<uint64_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics>
{
    int32_t WINRT_CALL get_ContentBytesReceivedCount(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentBytesReceivedCount, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ContentBytesReceivedCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeToHeadersReceived(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeToHeadersReceived, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().TimeToHeadersReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeToFirstByteReceived(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeToFirstByteReceived, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().TimeToFirstByteReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeToLastByteReceived(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeToLastByteReceived, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().TimeToLastByteReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs>
{
    int32_t WINRT_CALL get_OldValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AudioOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics> : produce_base<D, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>
{
    int32_t WINRT_CALL IsContentTypeSupported(void* contentType, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentTypeSupported, WINRT_WRAP(bool), hstring const&);
            *result = detach_from<bool>(this->shim().IsContentTypeSupported(*reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUriAsync(void* uri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>), Windows::Foundation::Uri const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>>(this->shim().CreateFromUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUriWithDownloaderAsync(void* uri, void* httpClient, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>), Windows::Foundation::Uri const, Windows::Web::Http::HttpClient const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>>(this->shim().CreateFromUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::HttpClient const*>(&httpClient)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamAsync(void* stream, void* uri, void* contentType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>), Windows::Storage::Streams::IInputStream const, Windows::Foundation::Uri const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamWithDownloaderAsync(void* stream, void* uri, void* contentType, void* httpClient, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>), Windows::Storage::Streams::IInputStream const, Windows::Foundation::Uri const, hstring const, Windows::Web::Http::HttpClient const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&contentType), *reinterpret_cast<Windows::Web::Http::HttpClient const*>(&httpClient)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Streaming::Adaptive {

inline bool AdaptiveMediaSource::IsContentTypeSupported(param::hstring const& contentType)
{
    return impl::call_factory<AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>([&](auto&& f) { return f.IsContentTypeSupported(contentType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> AdaptiveMediaSource::CreateFromUriAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>([&](auto&& f) { return f.CreateFromUriAsync(uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> AdaptiveMediaSource::CreateFromUriAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpClient const& httpClient)
{
    return impl::call_factory<AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>([&](auto&& f) { return f.CreateFromUriAsync(uri, httpClient); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> AdaptiveMediaSource::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType)
{
    return impl::call_factory<AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>([&](auto&& f) { return f.CreateFromStreamAsync(stream, uri, contentType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> AdaptiveMediaSource::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, Windows::Foundation::Uri const& uri, param::hstring const& contentType, Windows::Web::Http::HttpClient const& httpClient)
{
    return impl::call_factory<AdaptiveMediaSource, Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics>([&](auto&& f) { return f.CreateFromStreamAsync(stream, uri, contentType, httpClient); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSource3> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceAdvancedSettings> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCorrelatedTimes> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceCreationResult2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnosticAvailableEventArgs3> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDiagnostics> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadBitrateChangedEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadCompletedEventArgs3> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadFailedEventArgs3> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedDeferral> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadRequestedEventArgs3> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadResult2> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceDownloadStatistics> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourcePlaybackBitrateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::IAdaptiveMediaSourceStatics> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceAdvancedSettings> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCorrelatedTimes> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceCreationResult> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnosticAvailableEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDiagnostics> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadBitrateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedDeferral> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadResult> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourceDownloadStatistics> {};
template<> struct hash<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSourcePlaybackBitrateChangedEventArgs> {};

}
