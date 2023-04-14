// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::Bitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->put_Bitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::Bitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->get_Bitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::ChannelCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->put_ChannelCount(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::ChannelCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->get_ChannelCount(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::SampleRate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->put_SampleRate(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::SampleRate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->get_SampleRate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::BitsPerSample(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->put_BitsPerSample(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::BitsPerSample() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties)->get_BitsPerSample(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_MediaProperties_IAudioEncodingProperties2<D>::IsSpatial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties2)->get_IsSpatial(&value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingProperties3<D>::Copy() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingProperties3)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateAac(sampleRate, channelCount, bitrate, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateAacAdts(sampleRate, channelCount, bitrate, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateMp3(sampleRate, channelCount, bitrate, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreatePcm(sampleRate, channelCount, bitsPerSample, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateWma(sampleRate, channelCount, bitrate, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2<D>::CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2)->CreateAlac(sampleRate, channelCount, bitsPerSample, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2<D>::CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2)->CreateFlac(sampleRate, channelCount, bitsPerSample, put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData<D>::SetFormatUserData(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData)->SetFormatUserData(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData<D>::GetFormatUserData(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::ContainerEncodingProperties consume_Windows_Media_MediaProperties_IContainerEncodingProperties2<D>::Copy() const
{
    Windows::Media::MediaProperties::ContainerEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IContainerEncodingProperties2)->Copy(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::ConstrainedBaseline() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_ConstrainedBaseline(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Baseline() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Baseline(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Extended() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Extended(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Main() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Main(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High10() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High10(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High422() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High422(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High444() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High444(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::StereoHigh() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_StereoHigh(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::MultiviewHigh() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_MultiviewHigh(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Width(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingProperties)->put_Width(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingProperties)->get_Width(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Height(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingProperties)->put_Height(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingProperties)->get_Height(&value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingProperties2<D>::Copy() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingProperties2)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreateJpeg() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreateJpeg(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreatePng() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreatePng(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreateJpegXR() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreateJpegXR(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2<D>::CreateUncompressed(Windows::Media::MediaProperties::MediaPixelFormat const& format) const
{
    Windows::Media::MediaProperties::ImageEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2)->CreateUncompressed(get_abi(format), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2<D>::CreateBmp() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2)->CreateBmp(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::ImageEncodingProperties consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics3<D>::CreateHeif() const
{
    Windows::Media::MediaProperties::ImageEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3)->CreateHeif(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Audio(Windows::Media::MediaProperties::AudioEncodingProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Audio(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Audio() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Audio(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Video(Windows::Media::MediaProperties::VideoEncodingProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Video(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Video() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Video(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Container(Windows::Media::MediaProperties::ContainerEncodingProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Container(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::ContainerEncodingProperties consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Container() const
{
    Windows::Media::MediaProperties::ContainerEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Container(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::SetAudioTracks(param::iterable<Windows::Media::Core::AudioStreamDescriptor> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile2)->SetAudioTracks(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor> consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::GetAudioTracks() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile2)->GetAudioTracks(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::SetVideoTracks(param::iterable<Windows::Media::Core::VideoStreamDescriptor> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile2)->SetVideoTracks(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor> consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::GetVideoTracks() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile2)->GetVideoTracks(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProfile3<D>::SetTimedMetadataTracks(param::iterable<Windows::Media::Core::TimedMetadataStreamDescriptor> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile3)->SetTimedMetadataTracks(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedMetadataStreamDescriptor> consume_Windows_Media_MediaProperties_IMediaEncodingProfile3<D>::GetTimedMetadataTracks() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedMetadataStreamDescriptor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfile3)->GetTimedMetadataTracks(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateM4a(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateM4a(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateMp3(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateMp3(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateWma(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateWma(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateMp4(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateMp4(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateWmv(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateWmv(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateFromFileAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateFromFileAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateFromStreamAsync(get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2<D>::CreateWav(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics2)->CreateWav(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2<D>::CreateAvi(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics2)->CreateAvi(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateAlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateAlac(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateFlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateFlac(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateHevc(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
{
    Windows::Media::MediaProperties::MediaEncodingProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateHevc(get_abi(quality), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaPropertySet consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Properties() const
{
    Windows::Media::MediaProperties::MediaPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Type() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Subtype(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProperties)->put_Subtype(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Subtype() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Subtype(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Aac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Aac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AacAdts() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AacAdts(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Ac3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Ac3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AmrNb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AmrNb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AmrWb() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AmrWb(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Argb32() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Argb32(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Asf() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Asf(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Avi() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Avi(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Bgra8() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Bgra8(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Bmp() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Bmp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Eac3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Eac3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Float() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Float(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Gif() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Gif(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H263() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H263(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H264() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H264(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H264Es() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H264Es(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Hevc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Hevc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::HevcEs() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_HevcEs(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Iyuv() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Iyuv(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Jpeg() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Jpeg(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::JpegXr() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_JpegXr(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mjpg() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mjpg(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mp3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mp3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg4() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg4(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Nv12() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Nv12(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Pcm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Pcm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Png() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Png(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Rgb24() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Rgb24(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Rgb32() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Rgb32(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Tiff() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Tiff(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wave() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wave(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wma8() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wma8(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wma9() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wma9(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wmv3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wmv3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wvc1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wvc1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Yuy2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Yuy2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Yv12() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Yv12(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::Vp9() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_Vp9(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::L8() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_L8(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::L16() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_L16(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::D16() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_D16(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3<D>::Alac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3)->get_Alac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3<D>::Flac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3)->get_Flac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics4<D>::P010() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4)->get_P010(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics5<D>::Heif() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5)->get_Heif(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaRatio<D>::Numerator(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaRatio)->put_Numerator(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IMediaRatio<D>::Numerator() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaRatio)->get_Numerator(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IMediaRatio<D>::Denominator(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaRatio)->put_Denominator(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IMediaRatio<D>::Denominator() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMediaRatio)->get_Denominator(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::Simple() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_Simple(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::Main() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_Main(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::SignalNoiseRatioScalable() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_SignalNoiseRatioScalable(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::SpatiallyScalable() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_SpatiallyScalable(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::High() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_High(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::SetFormatUserData(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->SetFormatUserData(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::GetFormatUserData(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::TimedMetadataEncodingProperties consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::Copy() const
{
    Windows::Media::MediaProperties::TimedMetadataEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->Copy(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Bitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Bitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Bitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Bitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Width(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Width(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Width(&value));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Height(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Height(value));
}

template <typename D> uint32_t consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Height(&value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::FrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->get_FrameRate(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::PixelAspectRatio() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties)->get_PixelAspectRatio(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::SetFormatUserData(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties2)->SetFormatUserData(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::GetFormatUserData(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties2)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::ProfileId(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties2)->put_ProfileId(value));
}

template <typename D> int32_t consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::ProfileId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties2)->get_ProfileId(&value));
    return value;
}

template <typename D> Windows::Media::MediaProperties::StereoscopicVideoPackingMode consume_Windows_Media_MediaProperties_IVideoEncodingProperties3<D>::StereoscopicVideoPackingMode() const
{
    Windows::Media::MediaProperties::StereoscopicVideoPackingMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties3)->get_StereoscopicVideoPackingMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::SphericalVideoFrameFormat consume_Windows_Media_MediaProperties_IVideoEncodingProperties4<D>::SphericalVideoFrameFormat() const
{
    Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties4)->get_SphericalVideoFrameFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IVideoEncodingProperties5<D>::Copy() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingProperties5)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateH264() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateH264(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateMpeg2() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateMpeg2(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateUncompressed(param::hstring const& subtype, uint32_t width, uint32_t height) const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateUncompressed(get_abi(subtype), width, height, put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics2<D>::CreateHevc() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2)->CreateHevc(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingProperties>
{
    int32_t WINRT_CALL put_Bitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(void), uint32_t);
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChannelCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelCount, WINRT_WRAP(void), uint32_t);
            this->shim().ChannelCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ChannelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SampleRate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SampleRate, WINRT_WRAP(void), uint32_t);
            this->shim().SampleRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SampleRate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SampleRate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SampleRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BitsPerSample(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitsPerSample, WINRT_WRAP(void), uint32_t);
            this->shim().BitsPerSample(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitsPerSample(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitsPerSample, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BitsPerSample());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingProperties2> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingProperties2>
{
    int32_t WINRT_CALL get_IsSpatial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSpatial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSpatial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingProperties3> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingProperties3>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>
{
    int32_t WINRT_CALL CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAac, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAac(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAacAdts, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAacAdts(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMp3, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateMp3(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePcm, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreatePcm(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWma, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateWma(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>
{
    int32_t WINRT_CALL CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAlac, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAlac(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFlac, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties), uint32_t, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateFlac(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> : produce_base<D, Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>
{
    int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFormatUserData, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFormatUserData, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IContainerEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::IContainerEncodingProperties>
{};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IContainerEncodingProperties2> : produce_base<D, Windows::Media::MediaProperties::IContainerEncodingProperties2>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::MediaProperties::ContainerEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::ContainerEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IH264ProfileIdsStatics> : produce_base<D, Windows::Media::MediaProperties::IH264ProfileIdsStatics>
{
    int32_t WINRT_CALL get_ConstrainedBaseline(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConstrainedBaseline, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ConstrainedBaseline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Baseline(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Baseline, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Baseline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extended(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extended, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Extended());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Main(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Main, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Main());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_High(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(High, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().High());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_High10(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(High10, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().High10());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_High422(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(High422, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().High422());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_High444(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(High444, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().High444());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StereoHigh(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StereoHigh, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StereoHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MultiviewHigh(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MultiviewHigh, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MultiviewHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IImageEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::IImageEncodingProperties>
{
    int32_t WINRT_CALL put_Width(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(void), uint32_t);
            this->shim().Width(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Height(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(void), uint32_t);
            this->shim().Height(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IImageEncodingProperties2> : produce_base<D, Windows::Media::MediaProperties::IImageEncodingProperties2>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> : produce_base<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>
{
    int32_t WINRT_CALL CreateJpeg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateJpeg, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateJpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePng(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePng, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreatePng());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateJpegXR(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateJpegXR, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateJpegXR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> : produce_base<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>
{
    int32_t WINRT_CALL CreateUncompressed(Windows::Media::MediaProperties::MediaPixelFormat format, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUncompressed, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties), Windows::Media::MediaProperties::MediaPixelFormat const&);
            *value = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateUncompressed(*reinterpret_cast<Windows::Media::MediaProperties::MediaPixelFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBmp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBmp, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateBmp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> : produce_base<D, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>
{
    int32_t WINRT_CALL CreateHeif(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHeif, WINRT_WRAP(Windows::Media::MediaProperties::ImageEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateHeif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfile> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfile>
{
    int32_t WINRT_CALL put_Audio(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Audio, WINRT_WRAP(void), Windows::Media::MediaProperties::AudioEncodingProperties const&);
            this->shim().Audio(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Audio(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Audio, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().Audio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Video(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Video, WINRT_WRAP(void), Windows::Media::MediaProperties::VideoEncodingProperties const&);
            this->shim().Video(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Video(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Video, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().Video());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Container(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(void), Windows::Media::MediaProperties::ContainerEncodingProperties const&);
            this->shim().Container(*reinterpret_cast<Windows::Media::MediaProperties::ContainerEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::Media::MediaProperties::ContainerEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::ContainerEncodingProperties>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfile2> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfile2>
{
    int32_t WINRT_CALL SetAudioTracks(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAudioTracks, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Media::Core::AudioStreamDescriptor> const&);
            this->shim().SetAudioTracks(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Core::AudioStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioTracks, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor>>(this->shim().GetAudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVideoTracks(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVideoTracks, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Media::Core::VideoStreamDescriptor> const&);
            this->shim().SetVideoTracks(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Core::VideoStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVideoTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoTracks, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor>>(this->shim().GetVideoTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfile3> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfile3>
{
    int32_t WINRT_CALL SetTimedMetadataTracks(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTimedMetadataTracks, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Media::Core::TimedMetadataStreamDescriptor> const&);
            this->shim().SetTimedMetadataTracks(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Core::TimedMetadataStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTimedMetadataTracks(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTimedMetadataTracks, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedMetadataStreamDescriptor>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedMetadataStreamDescriptor>>(this->shim().GetTimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>
{
    int32_t WINRT_CALL CreateM4a(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateM4a, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateM4a(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMp3(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMp3, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateMp3(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWma(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWma, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWma(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMp4(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMp4, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::VideoEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateMp4(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWmv(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWmv, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::VideoEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWmv(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
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
            WINRT_ASSERT_DECLARATION(CreateFromFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile>>(this->shim().CreateFromFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamAsync(void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile>), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>
{
    int32_t WINRT_CALL CreateWav(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWav, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWav(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAvi(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAvi, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::VideoEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateAvi(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>
{
    int32_t WINRT_CALL CreateAlac(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAlac, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateAlac(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFlac(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFlac, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::AudioEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateFlac(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateHevc(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHevc, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile), Windows::Media::MediaProperties::VideoEncodingQuality const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateHevc(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingProperties>
{
    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Media::MediaProperties::MediaPropertySet));
            *value = detach_from<Windows::Media::MediaProperties::MediaPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subtype(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtype, WINRT_WRAP(void), hstring const&);
            this->shim().Subtype(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtype(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtype, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtype());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>
{
    int32_t WINRT_CALL get_Aac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Aac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AacAdts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AacAdts, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AacAdts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ac3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ac3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Ac3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AmrNb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AmrNb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AmrNb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AmrWb(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AmrWb, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AmrWb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Argb32(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Argb32, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Argb32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Asf(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Asf, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Asf());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Avi(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Avi, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Avi());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bgra8(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bgra8, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bgra8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bmp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bmp, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bmp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Eac3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Eac3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Eac3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Float(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Float, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Float());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gif(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gif, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Gif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_H263(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(H263, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().H263());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_H264(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(H264, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().H264());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_H264Es(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(H264Es, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().H264Es());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hevc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hevc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HevcEs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HevcEs, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HevcEs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Iyuv(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Iyuv, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Iyuv());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Jpeg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Jpeg, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Jpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JpegXr(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JpegXr, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JpegXr());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mjpg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mjpg, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mjpg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mpeg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mpeg, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mpeg1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mpeg1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mpeg1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mpeg2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mpeg2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mp3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mp3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mp3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mpeg4(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mpeg4, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Mpeg4());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nv12(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nv12, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Nv12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pcm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pcm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Png(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Png, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Png());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rgb24(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rgb24, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rgb24());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rgb32(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rgb32, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rgb32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tiff(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tiff, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tiff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wave(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wave, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wave());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wma8(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wma8, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wma8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wma9(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wma9, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wma9());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wmv3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wmv3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wmv3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wvc1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wvc1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Wvc1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Yuy2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Yuy2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Yuy2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Yv12(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Yv12, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Yv12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>
{
    int32_t WINRT_CALL get_Vp9(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vp9, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Vp9());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_L8(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(L8, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().L8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_L16(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(L16, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().L16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_D16(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(D16, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().D16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>
{
    int32_t WINRT_CALL get_Alac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Alac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Flac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Flac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>
{
    int32_t WINRT_CALL get_P010(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(P010, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().P010());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> : produce_base<D, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>
{
    int32_t WINRT_CALL get_Heif(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heif, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Heif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMediaRatio> : produce_base<D, Windows::Media::MediaProperties::IMediaRatio>
{
    int32_t WINRT_CALL put_Numerator(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Numerator, WINRT_WRAP(void), uint32_t);
            this->shim().Numerator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Numerator(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Numerator, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Numerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Denominator(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Denominator, WINRT_WRAP(void), uint32_t);
            this->shim().Denominator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Denominator(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Denominator, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Denominator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> : produce_base<D, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>
{
    int32_t WINRT_CALL get_Simple(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Simple, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Simple());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Main(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Main, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Main());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalNoiseRatioScalable(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalNoiseRatioScalable, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SignalNoiseRatioScalable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpatiallyScalable(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatiallyScalable, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SpatiallyScalable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_High(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(High, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().High());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>
{
    int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFormatUserData, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFormatUserData, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::MediaProperties::TimedMetadataEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingProperties> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingProperties>
{
    int32_t WINRT_CALL put_Bitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(void), uint32_t);
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Width(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(void), uint32_t);
            this->shim().Width(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Height(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(void), uint32_t);
            this->shim().Height(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().FrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelAspectRatio(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelAspectRatio, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().PixelAspectRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingProperties2> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingProperties2>
{
    int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFormatUserData, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFormatUserData, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProfileId(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileId, WINRT_WRAP(void), int32_t);
            this->shim().ProfileId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProfileId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ProfileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingProperties3> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingProperties3>
{
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
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingProperties4> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingProperties4>
{
    int32_t WINRT_CALL get_SphericalVideoFrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SphericalVideoFrameFormat, WINRT_WRAP(Windows::Media::MediaProperties::SphericalVideoFrameFormat));
            *value = detach_from<Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().SphericalVideoFrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingProperties5> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingProperties5>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *result = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>
{
    int32_t WINRT_CALL CreateH264(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateH264, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateH264());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMpeg2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMpeg2, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateMpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateUncompressed(void* subtype, uint32_t width, uint32_t height, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateUncompressed, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties), hstring const&, uint32_t, uint32_t);
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateUncompressed(*reinterpret_cast<hstring const*>(&subtype), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> : produce_base<D, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>
{
    int32_t WINRT_CALL CreateHevc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHevc, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateHevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

inline AudioEncodingProperties::AudioEncodingProperties() :
    AudioEncodingProperties(impl::call_factory<AudioEncodingProperties>([](auto&& f) { return f.template ActivateInstance<AudioEncodingProperties>(); }))
{}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>([&](auto&& f) { return f.CreateAac(sampleRate, channelCount, bitrate); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>([&](auto&& f) { return f.CreateAacAdts(sampleRate, channelCount, bitrate); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>([&](auto&& f) { return f.CreateMp3(sampleRate, channelCount, bitrate); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>([&](auto&& f) { return f.CreatePcm(sampleRate, channelCount, bitsPerSample); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>([&](auto&& f) { return f.CreateWma(sampleRate, channelCount, bitrate); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>([&](auto&& f) { return f.CreateAlac(sampleRate, channelCount, bitsPerSample); });
}

inline Windows::Media::MediaProperties::AudioEncodingProperties AudioEncodingProperties::CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
{
    return impl::call_factory<AudioEncodingProperties, Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>([&](auto&& f) { return f.CreateFlac(sampleRate, channelCount, bitsPerSample); });
}

inline ContainerEncodingProperties::ContainerEncodingProperties() :
    ContainerEncodingProperties(impl::call_factory<ContainerEncodingProperties>([](auto&& f) { return f.template ActivateInstance<ContainerEncodingProperties>(); }))
{}

inline int32_t H264ProfileIds::ConstrainedBaseline()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.ConstrainedBaseline(); });
}

inline int32_t H264ProfileIds::Baseline()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.Baseline(); });
}

inline int32_t H264ProfileIds::Extended()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.Extended(); });
}

inline int32_t H264ProfileIds::Main()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.Main(); });
}

inline int32_t H264ProfileIds::High()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.High(); });
}

inline int32_t H264ProfileIds::High10()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.High10(); });
}

inline int32_t H264ProfileIds::High422()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.High422(); });
}

inline int32_t H264ProfileIds::High444()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.High444(); });
}

inline int32_t H264ProfileIds::StereoHigh()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.StereoHigh(); });
}

inline int32_t H264ProfileIds::MultiviewHigh()
{
    return impl::call_factory<H264ProfileIds, Windows::Media::MediaProperties::IH264ProfileIdsStatics>([&](auto&& f) { return f.MultiviewHigh(); });
}

inline ImageEncodingProperties::ImageEncodingProperties() :
    ImageEncodingProperties(impl::call_factory<ImageEncodingProperties>([](auto&& f) { return f.template ActivateInstance<ImageEncodingProperties>(); }))
{}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreateJpeg()
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>([&](auto&& f) { return f.CreateJpeg(); });
}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreatePng()
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>([&](auto&& f) { return f.CreatePng(); });
}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreateJpegXR()
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>([&](auto&& f) { return f.CreateJpegXR(); });
}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreateUncompressed(Windows::Media::MediaProperties::MediaPixelFormat const& format)
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>([&](auto&& f) { return f.CreateUncompressed(format); });
}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreateBmp()
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>([&](auto&& f) { return f.CreateBmp(); });
}

inline Windows::Media::MediaProperties::ImageEncodingProperties ImageEncodingProperties::CreateHeif()
{
    return impl::call_factory<ImageEncodingProperties, Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>([&](auto&& f) { return f.CreateHeif(); });
}

inline MediaEncodingProfile::MediaEncodingProfile() :
    MediaEncodingProfile(impl::call_factory<MediaEncodingProfile>([](auto&& f) { return f.template ActivateInstance<MediaEncodingProfile>(); }))
{}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateM4a(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateM4a(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateMp3(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateMp3(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateWma(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateWma(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateMp4(Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateMp4(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateWmv(Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateWmv(quality); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> MediaEncodingProfile::CreateFromFileAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateFromFileAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> MediaEncodingProfile::CreateFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics>([&](auto&& f) { return f.CreateFromStreamAsync(stream); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateWav(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>([&](auto&& f) { return f.CreateWav(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateAvi(Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>([&](auto&& f) { return f.CreateAvi(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateAlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>([&](auto&& f) { return f.CreateAlac(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateFlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>([&](auto&& f) { return f.CreateFlac(quality); });
}

inline Windows::Media::MediaProperties::MediaEncodingProfile MediaEncodingProfile::CreateHevc(Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
{
    return impl::call_factory<MediaEncodingProfile, Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>([&](auto&& f) { return f.CreateHevc(quality); });
}

inline hstring MediaEncodingSubtypes::Aac()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Aac(); });
}

inline hstring MediaEncodingSubtypes::AacAdts()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.AacAdts(); });
}

inline hstring MediaEncodingSubtypes::Ac3()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Ac3(); });
}

inline hstring MediaEncodingSubtypes::AmrNb()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.AmrNb(); });
}

inline hstring MediaEncodingSubtypes::AmrWb()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.AmrWb(); });
}

inline hstring MediaEncodingSubtypes::Argb32()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Argb32(); });
}

inline hstring MediaEncodingSubtypes::Asf()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Asf(); });
}

inline hstring MediaEncodingSubtypes::Avi()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Avi(); });
}

inline hstring MediaEncodingSubtypes::Bgra8()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Bgra8(); });
}

inline hstring MediaEncodingSubtypes::Bmp()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Bmp(); });
}

inline hstring MediaEncodingSubtypes::Eac3()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Eac3(); });
}

inline hstring MediaEncodingSubtypes::Float()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Float(); });
}

inline hstring MediaEncodingSubtypes::Gif()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Gif(); });
}

inline hstring MediaEncodingSubtypes::H263()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.H263(); });
}

inline hstring MediaEncodingSubtypes::H264()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.H264(); });
}

inline hstring MediaEncodingSubtypes::H264Es()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.H264Es(); });
}

inline hstring MediaEncodingSubtypes::Hevc()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Hevc(); });
}

inline hstring MediaEncodingSubtypes::HevcEs()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.HevcEs(); });
}

inline hstring MediaEncodingSubtypes::Iyuv()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Iyuv(); });
}

inline hstring MediaEncodingSubtypes::Jpeg()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Jpeg(); });
}

inline hstring MediaEncodingSubtypes::JpegXr()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.JpegXr(); });
}

inline hstring MediaEncodingSubtypes::Mjpg()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mjpg(); });
}

inline hstring MediaEncodingSubtypes::Mpeg()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mpeg(); });
}

inline hstring MediaEncodingSubtypes::Mpeg1()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mpeg1(); });
}

inline hstring MediaEncodingSubtypes::Mpeg2()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mpeg2(); });
}

inline hstring MediaEncodingSubtypes::Mp3()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mp3(); });
}

inline hstring MediaEncodingSubtypes::Mpeg4()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Mpeg4(); });
}

inline hstring MediaEncodingSubtypes::Nv12()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Nv12(); });
}

inline hstring MediaEncodingSubtypes::Pcm()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Pcm(); });
}

inline hstring MediaEncodingSubtypes::Png()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Png(); });
}

inline hstring MediaEncodingSubtypes::Rgb24()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Rgb24(); });
}

inline hstring MediaEncodingSubtypes::Rgb32()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Rgb32(); });
}

inline hstring MediaEncodingSubtypes::Tiff()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Tiff(); });
}

inline hstring MediaEncodingSubtypes::Wave()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Wave(); });
}

inline hstring MediaEncodingSubtypes::Wma8()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Wma8(); });
}

inline hstring MediaEncodingSubtypes::Wma9()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Wma9(); });
}

inline hstring MediaEncodingSubtypes::Wmv3()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Wmv3(); });
}

inline hstring MediaEncodingSubtypes::Wvc1()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Wvc1(); });
}

inline hstring MediaEncodingSubtypes::Yuy2()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Yuy2(); });
}

inline hstring MediaEncodingSubtypes::Yv12()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>([&](auto&& f) { return f.Yv12(); });
}

inline hstring MediaEncodingSubtypes::Vp9()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>([&](auto&& f) { return f.Vp9(); });
}

inline hstring MediaEncodingSubtypes::L8()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>([&](auto&& f) { return f.L8(); });
}

inline hstring MediaEncodingSubtypes::L16()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>([&](auto&& f) { return f.L16(); });
}

inline hstring MediaEncodingSubtypes::D16()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>([&](auto&& f) { return f.D16(); });
}

inline hstring MediaEncodingSubtypes::Alac()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>([&](auto&& f) { return f.Alac(); });
}

inline hstring MediaEncodingSubtypes::Flac()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>([&](auto&& f) { return f.Flac(); });
}

inline hstring MediaEncodingSubtypes::P010()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>([&](auto&& f) { return f.P010(); });
}

inline hstring MediaEncodingSubtypes::Heif()
{
    return impl::call_factory<MediaEncodingSubtypes, Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>([&](auto&& f) { return f.Heif(); });
}

inline MediaPropertySet::MediaPropertySet() :
    MediaPropertySet(impl::call_factory<MediaPropertySet>([](auto&& f) { return f.template ActivateInstance<MediaPropertySet>(); }))
{}

inline int32_t Mpeg2ProfileIds::Simple()
{
    return impl::call_factory<Mpeg2ProfileIds, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>([&](auto&& f) { return f.Simple(); });
}

inline int32_t Mpeg2ProfileIds::Main()
{
    return impl::call_factory<Mpeg2ProfileIds, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>([&](auto&& f) { return f.Main(); });
}

inline int32_t Mpeg2ProfileIds::SignalNoiseRatioScalable()
{
    return impl::call_factory<Mpeg2ProfileIds, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>([&](auto&& f) { return f.SignalNoiseRatioScalable(); });
}

inline int32_t Mpeg2ProfileIds::SpatiallyScalable()
{
    return impl::call_factory<Mpeg2ProfileIds, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>([&](auto&& f) { return f.SpatiallyScalable(); });
}

inline int32_t Mpeg2ProfileIds::High()
{
    return impl::call_factory<Mpeg2ProfileIds, Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>([&](auto&& f) { return f.High(); });
}

inline TimedMetadataEncodingProperties::TimedMetadataEncodingProperties() :
    TimedMetadataEncodingProperties(impl::call_factory<TimedMetadataEncodingProperties>([](auto&& f) { return f.template ActivateInstance<TimedMetadataEncodingProperties>(); }))
{}

inline VideoEncodingProperties::VideoEncodingProperties() :
    VideoEncodingProperties(impl::call_factory<VideoEncodingProperties>([](auto&& f) { return f.template ActivateInstance<VideoEncodingProperties>(); }))
{}

inline Windows::Media::MediaProperties::VideoEncodingProperties VideoEncodingProperties::CreateH264()
{
    return impl::call_factory<VideoEncodingProperties, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>([&](auto&& f) { return f.CreateH264(); });
}

inline Windows::Media::MediaProperties::VideoEncodingProperties VideoEncodingProperties::CreateMpeg2()
{
    return impl::call_factory<VideoEncodingProperties, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>([&](auto&& f) { return f.CreateMpeg2(); });
}

inline Windows::Media::MediaProperties::VideoEncodingProperties VideoEncodingProperties::CreateUncompressed(param::hstring const& subtype, uint32_t width, uint32_t height)
{
    return impl::call_factory<VideoEncodingProperties, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>([&](auto&& f) { return f.CreateUncompressed(subtype, width, height); });
}

inline Windows::Media::MediaProperties::VideoEncodingProperties VideoEncodingProperties::CreateHevc()
{
    return impl::call_factory<VideoEncodingProperties, Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>([&](auto&& f) { return f.CreateHevc(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IImageEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingProperties2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IImageEncodingProperties2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaRatio> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMediaRatio> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::AudioEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::AudioEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::H264ProfileIds> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::H264ProfileIds> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::ImageEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::ImageEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::MediaEncodingProfile> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::MediaEncodingProfile> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::MediaEncodingSubtypes> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::MediaEncodingSubtypes> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::MediaPropertySet> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::MediaPropertySet> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::MediaRatio> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::MediaRatio> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::Mpeg2ProfileIds> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::Mpeg2ProfileIds> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties> {};
template<> struct hash<winrt::Windows::Media::MediaProperties::VideoEncodingProperties> : winrt::impl::hash_base<winrt::Windows::Media::MediaProperties::VideoEncodingProperties> {};

}
