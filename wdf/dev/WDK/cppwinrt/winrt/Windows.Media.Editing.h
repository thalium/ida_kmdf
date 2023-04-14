// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Transcoding.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.Editing.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::TrimTimeFromStart() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_TrimTimeFromStart(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::TrimTimeFromStart(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->put_TrimTimeFromStart(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::TrimTimeFromEnd() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_TrimTimeFromEnd(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::TrimTimeFromEnd(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->put_TrimTimeFromEnd(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::OriginalDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_OriginalDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::TrimmedDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_TrimmedDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::UserData() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_UserData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::Delay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->put_Delay(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::Delay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_Delay(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::Volume(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->put_Volume(value));
}

template <typename D> double consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_Volume(&value));
    return value;
}

template <typename D> Windows::Media::Editing::BackgroundAudioTrack consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::Clone() const
{
    Windows::Media::Editing::BackgroundAudioTrack value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->Clone(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::GetAudioEncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->GetAudioEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition> consume_Windows_Media_Editing_IBackgroundAudioTrack<D>::AudioEffectDefinitions() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrack)->get_AudioEffectDefinitions(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::BackgroundAudioTrack consume_Windows_Media_Editing_IBackgroundAudioTrackStatics<D>::CreateFromEmbeddedAudioTrack(Windows::Media::Editing::EmbeddedAudioTrack const& embeddedAudioTrack) const
{
    Windows::Media::Editing::BackgroundAudioTrack value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrackStatics)->CreateFromEmbeddedAudioTrack(get_abi(embeddedAudioTrack), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Editing::BackgroundAudioTrack> consume_Windows_Media_Editing_IBackgroundAudioTrackStatics<D>::CreateFromFileAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Editing::BackgroundAudioTrack> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IBackgroundAudioTrackStatics)->CreateFromFileAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Editing_IEmbeddedAudioTrack<D>::GetAudioEncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IEmbeddedAudioTrack)->GetAudioEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::TrimTimeFromStart() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_TrimTimeFromStart(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaClip<D>::TrimTimeFromStart(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->put_TrimTimeFromStart(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::TrimTimeFromEnd() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_TrimTimeFromEnd(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaClip<D>::TrimTimeFromEnd(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->put_TrimTimeFromEnd(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::OriginalDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_OriginalDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::TrimmedDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_TrimmedDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Media_Editing_IMediaClip<D>::UserData() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_UserData(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::MediaClip consume_Windows_Media_Editing_IMediaClip<D>::Clone() const
{
    Windows::Media::Editing::MediaClip result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->Clone(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::StartTimeInComposition() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_StartTimeInComposition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaClip<D>::EndTimeInComposition() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_EndTimeInComposition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Editing::EmbeddedAudioTrack> consume_Windows_Media_Editing_IMediaClip<D>::EmbeddedAudioTracks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Editing::EmbeddedAudioTrack> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_EmbeddedAudioTracks(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Editing_IMediaClip<D>::SelectedEmbeddedAudioTrackIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_SelectedEmbeddedAudioTrackIndex(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaClip<D>::SelectedEmbeddedAudioTrackIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->put_SelectedEmbeddedAudioTrackIndex(value));
}

template <typename D> void consume_Windows_Media_Editing_IMediaClip<D>::Volume(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->put_Volume(value));
}

template <typename D> double consume_Windows_Media_Editing_IMediaClip<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_Volume(&value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_Editing_IMediaClip<D>::GetVideoEncodingProperties() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->GetVideoEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition> consume_Windows_Media_Editing_IMediaClip<D>::AudioEffectDefinitions() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_AudioEffectDefinitions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Effects::IVideoEffectDefinition> consume_Windows_Media_Editing_IMediaClip<D>::VideoEffectDefinitions() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Effects::IVideoEffectDefinition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClip)->get_VideoEffectDefinitions(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::MediaClip consume_Windows_Media_Editing_IMediaClipStatics<D>::CreateFromColor(Windows::UI::Color const& color, Windows::Foundation::TimeSpan const& originalDuration) const
{
    Windows::Media::Editing::MediaClip value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClipStatics)->CreateFromColor(get_abi(color), get_abi(originalDuration), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> consume_Windows_Media_Editing_IMediaClipStatics<D>::CreateFromFileAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClipStatics)->CreateFromFileAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> consume_Windows_Media_Editing_IMediaClipStatics<D>::CreateFromImageFileAsync(Windows::Storage::IStorageFile const& file, Windows::Foundation::TimeSpan const& originalDuration) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClipStatics)->CreateFromImageFileAsync(get_abi(file), get_abi(originalDuration), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Editing::MediaClip consume_Windows_Media_Editing_IMediaClipStatics2<D>::CreateFromSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Foundation::TimeSpan const& originalDuration) const
{
    Windows::Media::Editing::MediaClip value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaClipStatics2)->CreateFromSurface(get_abi(surface), get_abi(originalDuration), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaComposition<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaClip> consume_Windows_Media_Editing_IMediaComposition<D>::Clips() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaClip> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->get_Clips(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Editing::BackgroundAudioTrack> consume_Windows_Media_Editing_IMediaComposition<D>::BackgroundAudioTracks() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Editing::BackgroundAudioTrack> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->get_BackgroundAudioTracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Media_Editing_IMediaComposition<D>::UserData() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->get_UserData(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::MediaComposition consume_Windows_Media_Editing_IMediaComposition<D>::Clone() const
{
    Windows::Media::Editing::MediaComposition result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->Clone(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Editing_IMediaComposition<D>::SaveAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->SaveAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> consume_Windows_Media_Editing_IMediaComposition<D>::GetThumbnailAsync(Windows::Foundation::TimeSpan const& timeFromStart, int32_t scaledWidth, int32_t scaledHeight, Windows::Media::Editing::VideoFramePrecision const& framePrecision) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->GetThumbnailAsync(get_abi(timeFromStart), scaledWidth, scaledHeight, get_abi(framePrecision), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::ImageStream>> consume_Windows_Media_Editing_IMediaComposition<D>::GetThumbnailsAsync(param::async_iterable<Windows::Foundation::TimeSpan> const& timesFromStart, int32_t scaledWidth, int32_t scaledHeight, Windows::Media::Editing::VideoFramePrecision const& framePrecision) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::ImageStream>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->GetThumbnailsAsync(get_abi(timesFromStart), scaledWidth, scaledHeight, get_abi(framePrecision), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> consume_Windows_Media_Editing_IMediaComposition<D>::RenderToFileAsync(Windows::Storage::IStorageFile const& destination) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->RenderToFileAsync(get_abi(destination), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> consume_Windows_Media_Editing_IMediaComposition<D>::RenderToFileAsync(Windows::Storage::IStorageFile const& destination, Windows::Media::Editing::MediaTrimmingPreference const& trimmingPreference) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->RenderToFileWithTrimmingPreferenceAsync(get_abi(destination), get_abi(trimmingPreference), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> consume_Windows_Media_Editing_IMediaComposition<D>::RenderToFileAsync(Windows::Storage::IStorageFile const& destination, Windows::Media::Editing::MediaTrimmingPreference const& trimmingPreference, Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->RenderToFileWithProfileAsync(get_abi(destination), get_abi(trimmingPreference), get_abi(encodingProfile), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_Editing_IMediaComposition<D>::CreateDefaultEncodingProfile() const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->CreateDefaultEncodingProfile(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Editing_IMediaComposition<D>::GenerateMediaStreamSource() const
{
    Windows::Media::Core::MediaStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->GenerateMediaStreamSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Editing_IMediaComposition<D>::GenerateMediaStreamSource(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile) const
{
    Windows::Media::Core::MediaStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->GenerateMediaStreamSourceWithProfile(get_abi(encodingProfile), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Editing_IMediaComposition<D>::GeneratePreviewMediaStreamSource(int32_t scaledWidth, int32_t scaledHeight) const
{
    Windows::Media::Core::MediaStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition)->GeneratePreviewMediaStreamSource(scaledWidth, scaledHeight, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlayLayer> consume_Windows_Media_Editing_IMediaComposition2<D>::OverlayLayers() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlayLayer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaComposition2)->get_OverlayLayers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaComposition> consume_Windows_Media_Editing_IMediaCompositionStatics<D>::LoadAsync(Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaComposition> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaCompositionStatics)->LoadAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Media_Editing_IMediaOverlay<D>::Position() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaOverlay<D>::Position(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->put_Position(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Editing_IMediaOverlay<D>::Delay(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->put_Delay(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Editing_IMediaOverlay<D>::Delay() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->get_Delay(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_Editing_IMediaOverlay<D>::Opacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaOverlay<D>::Opacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->put_Opacity(value));
}

template <typename D> Windows::Media::Editing::MediaOverlay consume_Windows_Media_Editing_IMediaOverlay<D>::Clone() const
{
    Windows::Media::Editing::MediaOverlay result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->Clone(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Editing::MediaClip consume_Windows_Media_Editing_IMediaOverlay<D>::Clip() const
{
    Windows::Media::Editing::MediaClip value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->get_Clip(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Editing_IMediaOverlay<D>::AudioEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->get_AudioEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Editing_IMediaOverlay<D>::AudioEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlay)->put_AudioEnabled(value));
}

template <typename D> Windows::Media::Editing::MediaOverlay consume_Windows_Media_Editing_IMediaOverlayFactory<D>::Create(Windows::Media::Editing::MediaClip const& clip) const
{
    Windows::Media::Editing::MediaOverlay mediaOverlay{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayFactory)->Create(get_abi(clip), put_abi(mediaOverlay)));
    return mediaOverlay;
}

template <typename D> Windows::Media::Editing::MediaOverlay consume_Windows_Media_Editing_IMediaOverlayFactory<D>::CreateWithPositionAndOpacity(Windows::Media::Editing::MediaClip const& clip, Windows::Foundation::Rect const& position, double opacity) const
{
    Windows::Media::Editing::MediaOverlay mediaOverlay{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayFactory)->CreateWithPositionAndOpacity(get_abi(clip), get_abi(position), opacity, put_abi(mediaOverlay)));
    return mediaOverlay;
}

template <typename D> Windows::Media::Editing::MediaOverlayLayer consume_Windows_Media_Editing_IMediaOverlayLayer<D>::Clone() const
{
    Windows::Media::Editing::MediaOverlayLayer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayLayer)->Clone(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlay> consume_Windows_Media_Editing_IMediaOverlayLayer<D>::Overlays() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlay> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayLayer)->get_Overlays(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Effects::IVideoCompositorDefinition consume_Windows_Media_Editing_IMediaOverlayLayer<D>::CustomCompositorDefinition() const
{
    Windows::Media::Effects::IVideoCompositorDefinition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayLayer)->get_CustomCompositorDefinition(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Editing::MediaOverlayLayer consume_Windows_Media_Editing_IMediaOverlayLayerFactory<D>::CreateWithCompositorDefinition(Windows::Media::Effects::IVideoCompositorDefinition const& compositorDefinition) const
{
    Windows::Media::Editing::MediaOverlayLayer mediaOverlayLayer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Editing::IMediaOverlayLayerFactory)->CreateWithCompositorDefinition(get_abi(compositorDefinition), put_abi(mediaOverlayLayer)));
    return mediaOverlayLayer;
}

template <typename D>
struct produce<D, Windows::Media::Editing::IBackgroundAudioTrack> : produce_base<D, Windows::Media::Editing::IBackgroundAudioTrack>
{
    int32_t WINRT_CALL get_TrimTimeFromStart(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromStart, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimTimeFromStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimTimeFromStart(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromStart, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TrimTimeFromStart(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimTimeFromEnd(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromEnd, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimTimeFromEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimTimeFromEnd(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromEnd, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TrimTimeFromEnd(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginalDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().OriginalDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimmedDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimmedDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimmedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserData, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().UserData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Delay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Delay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Delay());
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

    int32_t WINRT_CALL Clone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Media::Editing::BackgroundAudioTrack));
            *value = detach_from<Windows::Media::Editing::BackgroundAudioTrack>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().GetAudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEffectDefinitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEffectDefinitions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition>>(this->shim().AudioEffectDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IBackgroundAudioTrackStatics> : produce_base<D, Windows::Media::Editing::IBackgroundAudioTrackStatics>
{
    int32_t WINRT_CALL CreateFromEmbeddedAudioTrack(void* embeddedAudioTrack, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromEmbeddedAudioTrack, WINRT_WRAP(Windows::Media::Editing::BackgroundAudioTrack), Windows::Media::Editing::EmbeddedAudioTrack const&);
            *value = detach_from<Windows::Media::Editing::BackgroundAudioTrack>(this->shim().CreateFromEmbeddedAudioTrack(*reinterpret_cast<Windows::Media::Editing::EmbeddedAudioTrack const*>(&embeddedAudioTrack)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromFileAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Editing::BackgroundAudioTrack>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Editing::BackgroundAudioTrack>>(this->shim().CreateFromFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IEmbeddedAudioTrack> : produce_base<D, Windows::Media::Editing::IEmbeddedAudioTrack>
{
    int32_t WINRT_CALL GetAudioEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().GetAudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaClip> : produce_base<D, Windows::Media::Editing::IMediaClip>
{
    int32_t WINRT_CALL get_TrimTimeFromStart(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromStart, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimTimeFromStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimTimeFromStart(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromStart, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TrimTimeFromStart(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimTimeFromEnd(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromEnd, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimTimeFromEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimTimeFromEnd(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimTimeFromEnd, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TrimTimeFromEnd(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginalDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().OriginalDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimmedDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimmedDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrimmedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserData, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().UserData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Media::Editing::MediaClip));
            *result = detach_from<Windows::Media::Editing::MediaClip>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartTimeInComposition(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTimeInComposition, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().StartTimeInComposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndTimeInComposition(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTimeInComposition, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EndTimeInComposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmbeddedAudioTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmbeddedAudioTracks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Editing::EmbeddedAudioTrack>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Editing::EmbeddedAudioTrack>>(this->shim().EmbeddedAudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedEmbeddedAudioTrackIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedEmbeddedAudioTrackIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedEmbeddedAudioTrackIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedEmbeddedAudioTrackIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedEmbeddedAudioTrackIndex, WINRT_WRAP(void), uint32_t);
            this->shim().SelectedEmbeddedAudioTrackIndex(value);
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

    int32_t WINRT_CALL GetVideoEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().GetVideoEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEffectDefinitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEffectDefinitions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Effects::IAudioEffectDefinition>>(this->shim().AudioEffectDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEffectDefinitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEffectDefinitions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Effects::IVideoEffectDefinition>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Effects::IVideoEffectDefinition>>(this->shim().VideoEffectDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaClipStatics> : produce_base<D, Windows::Media::Editing::IMediaClipStatics>
{
    int32_t WINRT_CALL CreateFromColor(struct struct_Windows_UI_Color color, Windows::Foundation::TimeSpan originalDuration, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromColor, WINRT_WRAP(Windows::Media::Editing::MediaClip), Windows::UI::Color const&, Windows::Foundation::TimeSpan const&);
            *value = detach_from<Windows::Media::Editing::MediaClip>(this->shim().CreateFromColor(*reinterpret_cast<Windows::UI::Color const*>(&color), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&originalDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromFileAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip>>(this->shim().CreateFromFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromImageFileAsync(void* file, Windows::Foundation::TimeSpan originalDuration, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromImageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip>), Windows::Storage::IStorageFile const, Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip>>(this->shim().CreateFromImageFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&originalDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaClipStatics2> : produce_base<D, Windows::Media::Editing::IMediaClipStatics2>
{
    int32_t WINRT_CALL CreateFromSurface(void* surface, Windows::Foundation::TimeSpan originalDuration, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromSurface, WINRT_WRAP(Windows::Media::Editing::MediaClip), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&, Windows::Foundation::TimeSpan const&);
            *value = detach_from<Windows::Media::Editing::MediaClip>(this->shim().CreateFromSurface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&originalDuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaComposition> : produce_base<D, Windows::Media::Editing::IMediaComposition>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clips(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clips, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaClip>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaClip>>(this->shim().Clips());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundAudioTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundAudioTracks, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Editing::BackgroundAudioTrack>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Editing::BackgroundAudioTrack>>(this->shim().BackgroundAudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserData, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().UserData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Media::Editing::MediaComposition));
            *result = detach_from<Windows::Media::Editing::MediaComposition>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailAsync(Windows::Foundation::TimeSpan timeFromStart, int32_t scaledWidth, int32_t scaledHeight, Windows::Media::Editing::VideoFramePrecision framePrecision, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>), Windows::Foundation::TimeSpan const, int32_t, int32_t, Windows::Media::Editing::VideoFramePrecision const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>>(this->shim().GetThumbnailAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeFromStart), scaledWidth, scaledHeight, *reinterpret_cast<Windows::Media::Editing::VideoFramePrecision const*>(&framePrecision)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailsAsync(void* timesFromStart, int32_t scaledWidth, int32_t scaledHeight, Windows::Media::Editing::VideoFramePrecision framePrecision, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::ImageStream>>), Windows::Foundation::Collections::IIterable<Windows::Foundation::TimeSpan> const, int32_t, int32_t, Windows::Media::Editing::VideoFramePrecision const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::ImageStream>>>(this->shim().GetThumbnailsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::TimeSpan> const*>(&timesFromStart), scaledWidth, scaledHeight, *reinterpret_cast<Windows::Media::Editing::VideoFramePrecision const*>(&framePrecision)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderToFileAsync(void* destination, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderToFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>>(this->shim().RenderToFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderToFileWithTrimmingPreferenceAsync(void* destination, Windows::Media::Editing::MediaTrimmingPreference trimmingPreference, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderToFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>), Windows::Storage::IStorageFile const, Windows::Media::Editing::MediaTrimmingPreference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>>(this->shim().RenderToFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&destination), *reinterpret_cast<Windows::Media::Editing::MediaTrimmingPreference const*>(&trimmingPreference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderToFileWithProfileAsync(void* destination, Windows::Media::Editing::MediaTrimmingPreference trimmingPreference, void* encodingProfile, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderToFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>), Windows::Storage::IStorageFile const, Windows::Media::Editing::MediaTrimmingPreference const, Windows::Media::MediaProperties::MediaEncodingProfile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Transcoding::TranscodeFailureReason, double>>(this->shim().RenderToFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&destination), *reinterpret_cast<Windows::Media::Editing::MediaTrimmingPreference const*>(&trimmingPreference), *reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDefaultEncodingProfile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDefaultEncodingProfile, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile));
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateDefaultEncodingProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GenerateMediaStreamSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateMediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaStreamSource));
            *value = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().GenerateMediaStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GenerateMediaStreamSourceWithProfile(void* encodingProfile, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateMediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaStreamSource), Windows::Media::MediaProperties::MediaEncodingProfile const&);
            *value = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().GenerateMediaStreamSource(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GeneratePreviewMediaStreamSource(int32_t scaledWidth, int32_t scaledHeight, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratePreviewMediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaStreamSource), int32_t, int32_t);
            *value = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().GeneratePreviewMediaStreamSource(scaledWidth, scaledHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaComposition2> : produce_base<D, Windows::Media::Editing::IMediaComposition2>
{
    int32_t WINRT_CALL get_OverlayLayers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverlayLayers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlayLayer>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlayLayer>>(this->shim().OverlayLayers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaCompositionStatics> : produce_base<D, Windows::Media::Editing::IMediaCompositionStatics>
{
    int32_t WINRT_CALL LoadAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaComposition>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaComposition>>(this->shim().LoadAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaOverlay> : produce_base<D, Windows::Media::Editing::IMediaOverlay>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Position(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Delay(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Delay(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delay(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delay, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Opacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Opacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(void), double);
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Media::Editing::MediaOverlay));
            *result = detach_from<Windows::Media::Editing::MediaOverlay>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clip(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clip, WINRT_WRAP(Windows::Media::Editing::MediaClip));
            *value = detach_from<Windows::Media::Editing::MediaClip>(this->shim().Clip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AudioEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEnabled, WINRT_WRAP(void), bool);
            this->shim().AudioEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaOverlayFactory> : produce_base<D, Windows::Media::Editing::IMediaOverlayFactory>
{
    int32_t WINRT_CALL Create(void* clip, void** mediaOverlay) noexcept final
    {
        try
        {
            *mediaOverlay = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Editing::MediaOverlay), Windows::Media::Editing::MediaClip const&);
            *mediaOverlay = detach_from<Windows::Media::Editing::MediaOverlay>(this->shim().Create(*reinterpret_cast<Windows::Media::Editing::MediaClip const*>(&clip)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPositionAndOpacity(void* clip, Windows::Foundation::Rect position, double opacity, void** mediaOverlay) noexcept final
    {
        try
        {
            *mediaOverlay = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPositionAndOpacity, WINRT_WRAP(Windows::Media::Editing::MediaOverlay), Windows::Media::Editing::MediaClip const&, Windows::Foundation::Rect const&, double);
            *mediaOverlay = detach_from<Windows::Media::Editing::MediaOverlay>(this->shim().CreateWithPositionAndOpacity(*reinterpret_cast<Windows::Media::Editing::MediaClip const*>(&clip), *reinterpret_cast<Windows::Foundation::Rect const*>(&position), opacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaOverlayLayer> : produce_base<D, Windows::Media::Editing::IMediaOverlayLayer>
{
    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Media::Editing::MediaOverlayLayer));
            *result = detach_from<Windows::Media::Editing::MediaOverlayLayer>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Overlays(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Overlays, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlay>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Editing::MediaOverlay>>(this->shim().Overlays());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomCompositorDefinition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomCompositorDefinition, WINRT_WRAP(Windows::Media::Effects::IVideoCompositorDefinition));
            *value = detach_from<Windows::Media::Effects::IVideoCompositorDefinition>(this->shim().CustomCompositorDefinition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Editing::IMediaOverlayLayerFactory> : produce_base<D, Windows::Media::Editing::IMediaOverlayLayerFactory>
{
    int32_t WINRT_CALL CreateWithCompositorDefinition(void* compositorDefinition, void** mediaOverlayLayer) noexcept final
    {
        try
        {
            *mediaOverlayLayer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithCompositorDefinition, WINRT_WRAP(Windows::Media::Editing::MediaOverlayLayer), Windows::Media::Effects::IVideoCompositorDefinition const&);
            *mediaOverlayLayer = detach_from<Windows::Media::Editing::MediaOverlayLayer>(this->shim().CreateWithCompositorDefinition(*reinterpret_cast<Windows::Media::Effects::IVideoCompositorDefinition const*>(&compositorDefinition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Editing {

inline Windows::Media::Editing::BackgroundAudioTrack BackgroundAudioTrack::CreateFromEmbeddedAudioTrack(Windows::Media::Editing::EmbeddedAudioTrack const& embeddedAudioTrack)
{
    return impl::call_factory<BackgroundAudioTrack, Windows::Media::Editing::IBackgroundAudioTrackStatics>([&](auto&& f) { return f.CreateFromEmbeddedAudioTrack(embeddedAudioTrack); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Editing::BackgroundAudioTrack> BackgroundAudioTrack::CreateFromFileAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<BackgroundAudioTrack, Windows::Media::Editing::IBackgroundAudioTrackStatics>([&](auto&& f) { return f.CreateFromFileAsync(file); });
}

inline Windows::Media::Editing::MediaClip MediaClip::CreateFromColor(Windows::UI::Color const& color, Windows::Foundation::TimeSpan const& originalDuration)
{
    return impl::call_factory<MediaClip, Windows::Media::Editing::IMediaClipStatics>([&](auto&& f) { return f.CreateFromColor(color, originalDuration); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> MediaClip::CreateFromFileAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<MediaClip, Windows::Media::Editing::IMediaClipStatics>([&](auto&& f) { return f.CreateFromFileAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaClip> MediaClip::CreateFromImageFileAsync(Windows::Storage::IStorageFile const& file, Windows::Foundation::TimeSpan const& originalDuration)
{
    return impl::call_factory<MediaClip, Windows::Media::Editing::IMediaClipStatics>([&](auto&& f) { return f.CreateFromImageFileAsync(file, originalDuration); });
}

inline Windows::Media::Editing::MediaClip MediaClip::CreateFromSurface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Foundation::TimeSpan const& originalDuration)
{
    return impl::call_factory<MediaClip, Windows::Media::Editing::IMediaClipStatics2>([&](auto&& f) { return f.CreateFromSurface(surface, originalDuration); });
}

inline MediaComposition::MediaComposition() :
    MediaComposition(impl::call_factory<MediaComposition>([](auto&& f) { return f.template ActivateInstance<MediaComposition>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Editing::MediaComposition> MediaComposition::LoadAsync(Windows::Storage::StorageFile const& file)
{
    return impl::call_factory<MediaComposition, Windows::Media::Editing::IMediaCompositionStatics>([&](auto&& f) { return f.LoadAsync(file); });
}

inline MediaOverlay::MediaOverlay(Windows::Media::Editing::MediaClip const& clip) :
    MediaOverlay(impl::call_factory<MediaOverlay, Windows::Media::Editing::IMediaOverlayFactory>([&](auto&& f) { return f.Create(clip); }))
{}

inline MediaOverlay::MediaOverlay(Windows::Media::Editing::MediaClip const& clip, Windows::Foundation::Rect const& position, double opacity) :
    MediaOverlay(impl::call_factory<MediaOverlay, Windows::Media::Editing::IMediaOverlayFactory>([&](auto&& f) { return f.CreateWithPositionAndOpacity(clip, position, opacity); }))
{}

inline MediaOverlayLayer::MediaOverlayLayer() :
    MediaOverlayLayer(impl::call_factory<MediaOverlayLayer>([](auto&& f) { return f.template ActivateInstance<MediaOverlayLayer>(); }))
{}

inline MediaOverlayLayer::MediaOverlayLayer(Windows::Media::Effects::IVideoCompositorDefinition const& compositorDefinition) :
    MediaOverlayLayer(impl::call_factory<MediaOverlayLayer, Windows::Media::Editing::IMediaOverlayLayerFactory>([&](auto&& f) { return f.CreateWithCompositorDefinition(compositorDefinition); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Editing::IBackgroundAudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IBackgroundAudioTrack> {};
template<> struct hash<winrt::Windows::Media::Editing::IBackgroundAudioTrackStatics> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IBackgroundAudioTrackStatics> {};
template<> struct hash<winrt::Windows::Media::Editing::IEmbeddedAudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IEmbeddedAudioTrack> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaClip> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaClip> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaClipStatics> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaClipStatics> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaClipStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaClipStatics2> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaComposition> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaComposition> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaComposition2> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaComposition2> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaCompositionStatics> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaCompositionStatics> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaOverlay> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaOverlay> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaOverlayFactory> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaOverlayFactory> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaOverlayLayer> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaOverlayLayer> {};
template<> struct hash<winrt::Windows::Media::Editing::IMediaOverlayLayerFactory> : winrt::impl::hash_base<winrt::Windows::Media::Editing::IMediaOverlayLayerFactory> {};
template<> struct hash<winrt::Windows::Media::Editing::BackgroundAudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Editing::BackgroundAudioTrack> {};
template<> struct hash<winrt::Windows::Media::Editing::EmbeddedAudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Editing::EmbeddedAudioTrack> {};
template<> struct hash<winrt::Windows::Media::Editing::MediaClip> : winrt::impl::hash_base<winrt::Windows::Media::Editing::MediaClip> {};
template<> struct hash<winrt::Windows::Media::Editing::MediaComposition> : winrt::impl::hash_base<winrt::Windows::Media::Editing::MediaComposition> {};
template<> struct hash<winrt::Windows::Media::Editing::MediaOverlay> : winrt::impl::hash_base<winrt::Windows::Media::Editing::MediaOverlay> {};
template<> struct hash<winrt::Windows::Media::Editing::MediaOverlayLayer> : winrt::impl::hash_base<winrt::Windows::Media::Editing::MediaOverlayLayer> {};

}
