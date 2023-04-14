// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/impl/Windows.Media.FaceAnalysis.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Media.Streaming.Adaptive.2.h"
#include "winrt/impl/Windows.Networking.BackgroundTransfer.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Core_IAudioStreamDescriptor<D>::EncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties encodingProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor)->get_EncodingProperties(put_abi(encodingProperties)));
    return encodingProperties;
}

template <typename D> void consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::LeadingEncoderPadding(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor2)->put_LeadingEncoderPadding(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::LeadingEncoderPadding() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor2)->get_LeadingEncoderPadding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::TrailingEncoderPadding(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor2)->put_TrailingEncoderPadding(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::TrailingEncoderPadding() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor2)->get_TrailingEncoderPadding(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::AudioStreamDescriptor consume_Windows_Media_Core_IAudioStreamDescriptor3<D>::Copy() const
{
    Windows::Media::Core::AudioStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptor3)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::AudioStreamDescriptor consume_Windows_Media_Core_IAudioStreamDescriptorFactory<D>::Create(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
{
    Windows::Media::Core::AudioStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioStreamDescriptorFactory)->Create(get_abi(encodingProperties), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::AudioTrack, Windows::Media::Core::AudioTrackOpenFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrack)->add_OpenFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed_revoker consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::AudioTrack, Windows::Media::Core::AudioTrackOpenFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
}

template <typename D> void consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IAudioTrack)->remove_OpenFailed(get_abi(token)));
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Core_IAudioTrack<D>::GetEncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrack)->GetEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Core_IAudioTrack<D>::PlaybackItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrack)->get_PlaybackItem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_IAudioTrack<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrack)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::AudioTrackSupportInfo consume_Windows_Media_Core_IAudioTrack<D>::SupportInfo() const
{
    Windows::Media::Core::AudioTrackSupportInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrack)->get_SupportInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Core_IAudioTrackOpenFailedEventArgs<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrackOpenFailedEventArgs)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaDecoderStatus consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::DecoderStatus() const
{
    Windows::Media::Core::MediaDecoderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrackSupportInfo)->get_DecoderStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::AudioDecoderDegradation consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::Degradation() const
{
    Windows::Media::Core::AudioDecoderDegradation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrackSupportInfo)->get_Degradation(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::AudioDecoderDegradationReason consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::DegradationReason() const
{
    Windows::Media::Core::AudioDecoderDegradationReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrackSupportInfo)->get_DegradationReason(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSourceStatus consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::MediaSourceStatus() const
{
    Windows::Media::Core::MediaSourceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IAudioTrackSupportInfo)->get_MediaSourceStatus(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IChapterCue<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IChapterCue)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IChapterCue<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IChapterCue)->get_Title(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::CodecKind consume_Windows_Media_Core_ICodecInfo<D>::Kind() const
{
    Windows::Media::Core::CodecKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecInfo)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::CodecCategory consume_Windows_Media_Core_ICodecInfo<D>::Category() const
{
    Windows::Media::Core::CodecCategory value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecInfo)->get_Category(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_Core_ICodecInfo<D>::Subtypes() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecInfo)->get_Subtypes(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Core_ICodecInfo<D>::IsTrusted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecInfo)->get_IsTrusted(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::CodecInfo>> consume_Windows_Media_Core_ICodecQuery<D>::FindAllAsync(Windows::Media::Core::CodecKind const& kind, Windows::Media::Core::CodecCategory const& category, param::hstring const& subType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::CodecInfo>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecQuery)->FindAllAsync(get_abi(kind), get_abi(category), get_abi(subType), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDV25() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDV25(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDV50() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDV50(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvh1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvh1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvhD() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvhD(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvsd() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvsd(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvsl() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvsl(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH263() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH263(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH264() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH264(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH265() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH265(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH264ES() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH264ES(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatHevc() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatHevc(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatHevcES() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatHevcES(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatM4S2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatM4S2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMjpg() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMjpg(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP43() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP43(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP4S() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP4S(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP4V() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP4V(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMpeg2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMpeg2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatVP80() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatVP80(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatVP90() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatVP90(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMpg1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMpg1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMss1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMss1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMss2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMss2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv2() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv2(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWvc1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWvc1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormat420O() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormat420O(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAdts() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAdts(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAlac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAlac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrNB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrNB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrWB() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrWB(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrWP() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrWP(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyAC3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyAC3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyAC3Spdif() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyAC3Spdif(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyDDPlus() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyDDPlus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDrm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDrm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDts() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDts(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatFlac() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatFlac(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatFloat() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatFloat(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMP3() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMP3(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMPeg() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMPeg(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMsp1() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMsp1(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatOpus() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatOpus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatPcm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatPcm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWmaSpdif() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWmaSpdif(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioLossless() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioLossless(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioV8() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioV8(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioV9() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioV9(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IDataCue<D>::Data(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IDataCue)->put_Data(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Core_IDataCue<D>::Data() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IDataCue)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::PropertySet consume_Windows_Media_Core_IDataCue2<D>::Properties() const
{
    Windows::Foundation::Collections::PropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IDataCue2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::FaceDetectionEffectFrame consume_Windows_Media_Core_IFaceDetectedEventArgs<D>::ResultFrame() const
{
    Windows::Media::Core::FaceDetectionEffectFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectedEventArgs)->get_ResultFrame(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IFaceDetectionEffect<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->put_Enabled(value));
}

template <typename D> bool consume_Windows_Media_Core_IFaceDetectionEffect<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IFaceDetectionEffect<D>::DesiredDetectionInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->put_DesiredDetectionInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IFaceDetectionEffect<D>::DesiredDetectionInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->get_DesiredDetectionInterval(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(Windows::Foundation::TypedEventHandler<Windows::Media::Core::FaceDetectionEffect, Windows::Media::Core::FaceDetectedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->add_FaceDetected(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected_revoker consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::FaceDetectionEffect, Windows::Media::Core::FaceDetectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FaceDetected_revoker>(this, FaceDetected(handler));
}

template <typename D> void consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffect)->remove_FaceDetected(get_abi(cookie)));
}

template <typename D> void consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::DetectionMode(Windows::Media::Core::FaceDetectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffectDefinition)->put_DetectionMode(get_abi(value)));
}

template <typename D> Windows::Media::Core::FaceDetectionMode consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::DetectionMode() const
{
    Windows::Media::Core::FaceDetectionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffectDefinition)->get_DetectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::SynchronousDetectionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffectDefinition)->put_SynchronousDetectionEnabled(value));
}

template <typename D> bool consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::SynchronousDetectionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffectDefinition)->get_SynchronousDetectionEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::FaceAnalysis::DetectedFace> consume_Windows_Media_Core_IFaceDetectionEffectFrame<D>::DetectedFaces() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::FaceAnalysis::DetectedFace> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IFaceDetectionEffectFrame)->get_DetectedFaces(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IHighDynamicRangeControl<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IHighDynamicRangeControl)->put_Enabled(value));
}

template <typename D> bool consume_Windows_Media_Core_IHighDynamicRangeControl<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IHighDynamicRangeControl)->get_Enabled(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Core_IHighDynamicRangeOutput<D>::Certainty() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IHighDynamicRangeOutput)->get_Certainty(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::Core::FrameController> consume_Windows_Media_Core_IHighDynamicRangeOutput<D>::FrameControllers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::Core::FrameController> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IHighDynamicRangeOutput)->get_FrameControllers(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextPoint consume_Windows_Media_Core_IImageCue<D>::Position() const
{
    Windows::Media::Core::TimedTextPoint value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IImageCue<D>::Position(Windows::Media::Core::TimedTextPoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->put_Position(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextSize consume_Windows_Media_Core_IImageCue<D>::Extent() const
{
    Windows::Media::Core::TimedTextSize value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->get_Extent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IImageCue<D>::Extent(Windows::Media::Core::TimedTextSize const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->put_Extent(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IImageCue<D>::SoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->put_SoftwareBitmap(get_abi(value)));
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Media_Core_IImageCue<D>::SoftwareBitmap() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IImageCue)->get_SoftwareBitmap(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::Source() const
{
    Windows::Media::Core::MediaStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::RandomAccessStream() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->get_RandomAccessStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Media_Core_ILowLightFusionResult<D>::Frame() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ILowLightFusionResult)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapPixelFormat> consume_Windows_Media_Core_ILowLightFusionStatics<D>::SupportedBitmapPixelFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapPixelFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ILowLightFusionStatics)->get_SupportedBitmapPixelFormats(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Media_Core_ILowLightFusionStatics<D>::MaxSupportedFrameCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ILowLightFusionStatics)->get_MaxSupportedFrameCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Core::LowLightFusionResult, double> consume_Windows_Media_Core_ILowLightFusionStatics<D>::FuseAsync(param::async_iterable<Windows::Graphics::Imaging::SoftwareBitmap> const& frameSet) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Core::LowLightFusionResult, double> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ILowLightFusionStatics)->FuseAsync(get_abi(frameSet), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaBinder<D>::Binding(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBinder, Windows::Media::Core::MediaBindingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBinder)->add_Binding(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaBinder<D>::Binding_revoker consume_Windows_Media_Core_IMediaBinder<D>::Binding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBinder, Windows::Media::Core::MediaBindingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Binding_revoker>(this, Binding(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaBinder<D>::Binding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaBinder)->remove_Binding(get_abi(token)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaBinder<D>::Token() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBinder)->get_Token(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaBinder<D>::Token(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBinder)->put_Token(get_abi(value)));
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaBinder<D>::Source() const
{
    Windows::Media::Core::MediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBinder)->get_Source(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBindingEventArgs, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->add_Canceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled_revoker consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBindingEventArgs, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Canceled_revoker>(this, Canceled(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->remove_Canceled(get_abi(token)));
}

template <typename D> Windows::Media::Core::MediaBinder consume_Windows_Media_Core_IMediaBindingEventArgs<D>::MediaBinder() const
{
    Windows::Media::Core::MediaBinder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->get_MediaBinder(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Media_Core_IMediaBindingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetUri(Windows::Foundation::Uri const& uri) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->SetUri(get_abi(uri)));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetStream(Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->SetStream(get_abi(stream), get_abi(contentType)));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetStreamReference(Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs)->SetStreamReference(get_abi(stream), get_abi(contentType)));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs2<D>::SetAdaptiveMediaSource(Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs2)->SetAdaptiveMediaSource(get_abi(mediaSource)));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs2<D>::SetStorageFile(Windows::Storage::IStorageFile const& file) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs2)->SetStorageFile(get_abi(file)));
}

template <typename D> void consume_Windows_Media_Core_IMediaBindingEventArgs3<D>::SetDownloadOperation(Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaBindingEventArgs3)->SetDownloadOperation(get_abi(downloadOperation)));
}

template <typename D> void consume_Windows_Media_Core_IMediaCue<D>::StartTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->put_StartTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaCue<D>::StartTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaCue<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaCue<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaCue<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaCue<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCue)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::IMediaCue consume_Windows_Media_Core_IMediaCueEventArgs<D>::Cue() const
{
    Windows::Media::Core::IMediaCue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaCueEventArgs)->get_Cue(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->add_OpenOperationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted_revoker consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OpenOperationCompleted_revoker>(this, OpenOperationCompleted(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaSource2)->remove_OpenOperationCompleted(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Media_Core_IMediaSource2<D>::CustomProperties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->get_CustomProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Core_IMediaSource2<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Core_IMediaSource2<D>::IsOpen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->get_IsOpen(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedTextSource> consume_Windows_Media_Core_IMediaSource2<D>::ExternalTimedTextSources() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedTextSource> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->get_ExternalTimedTextSources(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedMetadataTrack> consume_Windows_Media_Core_IMediaSource2<D>::ExternalTimedMetadataTracks() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedMetadataTrack> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource2)->get_ExternalTimedMetadataTracks(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource3)->add_StateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaSource3<D>::StateChanged_revoker consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaSource3)->remove_StateChanged(get_abi(token)));
}

template <typename D> Windows::Media::Core::MediaSourceState consume_Windows_Media_Core_IMediaSource3<D>::State() const
{
    Windows::Media::Core::MediaSourceState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource3)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaSource3<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource3)->Reset());
}

template <typename D> Windows::Media::Streaming::Adaptive::AdaptiveMediaSource consume_Windows_Media_Core_IMediaSource4<D>::AdaptiveMediaSource() const
{
    Windows::Media::Streaming::Adaptive::AdaptiveMediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource4)->get_AdaptiveMediaSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Core_IMediaSource4<D>::MediaStreamSource() const
{
    Windows::Media::Core::MediaStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource4)->get_MediaStreamSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MseStreamSource consume_Windows_Media_Core_IMediaSource4<D>::MseStreamSource() const
{
    Windows::Media::Core::MseStreamSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource4)->get_MseStreamSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Core_IMediaSource4<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource4)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Core_IMediaSource4<D>::OpenAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource4)->OpenAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Networking::BackgroundTransfer::DownloadOperation consume_Windows_Media_Core_IMediaSource5<D>::DownloadOperation() const
{
    Windows::Networking::BackgroundTransfer::DownloadOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSource5)->get_DownloadOperation(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSourceAppServiceConnection, Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceAppServiceConnection)->add_InitializeMediaStreamSourceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested_revoker consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSourceAppServiceConnection, Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InitializeMediaStreamSourceRequested_revoker>(this, InitializeMediaStreamSourceRequested(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaSourceAppServiceConnection)->remove_InitializeMediaStreamSourceRequested(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceAppServiceConnection)->Start());
}

template <typename D> Windows::Media::Core::MediaSourceAppServiceConnection consume_Windows_Media_Core_IMediaSourceAppServiceConnectionFactory<D>::Create(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) const
{
    Windows::Media::Core::MediaSourceAppServiceConnection result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceAppServiceConnectionFactory)->Create(get_abi(appServiceConnection), put_abi(result)));
    return result;
}

template <typename D> winrt::hresult consume_Windows_Media_Core_IMediaSourceError<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceError)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSourceError consume_Windows_Media_Core_IMediaSourceOpenOperationCompletedEventArgs<D>::Error() const
{
    Windows::Media::Core::MediaSourceError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSourceState consume_Windows_Media_Core_IMediaSourceStateChangedEventArgs<D>::OldState() const
{
    Windows::Media::Core::MediaSourceState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStateChangedEventArgs)->get_OldState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSourceState consume_Windows_Media_Core_IMediaSourceStateChangedEventArgs<D>::NewState() const
{
    Windows::Media::Core::MediaSourceState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStateChangedEventArgs)->get_NewState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromAdaptiveMediaSource(Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromAdaptiveMediaSource(get_abi(mediaSource), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromMediaStreamSource(Windows::Media::Core::MediaStreamSource const& mediaSource) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromMediaStreamSource(get_abi(mediaSource), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromMseStreamSource(Windows::Media::Core::MseStreamSource const& mediaSource) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromMseStreamSource(get_abi(mediaSource), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromIMediaSource(Windows::Media::Core::IMediaSource const& mediaSource) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromIMediaSource(get_abi(mediaSource), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStorageFile(Windows::Storage::IStorageFile const& file) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromStorageFile(get_abi(file), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromStream(get_abi(stream), get_abi(contentType), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStreamReference(Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromStreamReference(get_abi(stream), get_abi(contentType), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromUri(Windows::Foundation::Uri const& uri) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics)->CreateFromUri(get_abi(uri), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics2<D>::CreateFromMediaBinder(Windows::Media::Core::MediaBinder const& binder) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics2)->CreateFromMediaBinder(get_abi(binder), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics3<D>::CreateFromMediaFrameSource(Windows::Media::Capture::Frames::MediaFrameSource const& frameSource) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics3)->CreateFromMediaFrameSource(get_abi(frameSource), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaSource consume_Windows_Media_Core_IMediaSourceStatics4<D>::CreateFromDownloadOperation(Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation) const
{
    Windows::Media::Core::MediaSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaSourceStatics4)->CreateFromDownloadOperation(get_abi(downloadOperation), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Media_Core_IMediaStreamDescriptor<D>::IsSelected() const
{
    bool selected{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor)->get_IsSelected(&selected));
    return selected;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor)->put_Language(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamDescriptor2<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor2)->put_Label(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaStreamDescriptor2<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamDescriptor2)->get_Label(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSample, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->add_Processed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSample<D>::Processed_revoker consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSample, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Processed_revoker>(this, Processed(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->remove_Processed(get_abi(token)));
}

template <typename D> Windows::Storage::Streams::Buffer consume_Windows_Media_Core_IMediaStreamSample<D>::Buffer() const
{
    Windows::Storage::Streams::Buffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_Buffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSample<D>::Timestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSamplePropertySet consume_Windows_Media_Core_IMediaStreamSample<D>::ExtendedProperties() const
{
    Windows::Media::Core::MediaStreamSamplePropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_ExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSampleProtectionProperties consume_Windows_Media_Core_IMediaStreamSample<D>::Protection() const
{
    Windows::Media::Core::MediaStreamSampleProtectionProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_Protection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSample<D>::DecodeTimestamp(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->put_DecodeTimestamp(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSample<D>::DecodeTimestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_DecodeTimestamp(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSample<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSample<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSample<D>::KeyFrame(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->put_KeyFrame(value));
}

template <typename D> bool consume_Windows_Media_Core_IMediaStreamSample<D>::KeyFrame() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_KeyFrame(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSample<D>::Discontinuous(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->put_Discontinuous(value));
}

template <typename D> bool consume_Windows_Media_Core_IMediaStreamSample<D>::Discontinuous() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample)->get_Discontinuous(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Media_Core_IMediaStreamSample2<D>::Direct3D11Surface() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSample2)->get_Direct3D11Surface(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetKeyIdentifier(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetKeyIdentifier(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetKeyIdentifier(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetKeyIdentifier(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetInitializationVector(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetInitializationVector(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetInitializationVector(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetInitializationVector(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetSubSampleMapping(array_view<uint8_t const> value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetSubSampleMapping(value.size(), get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetSubSampleMapping(com_array<uint8_t>& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetSubSampleMapping(impl::put_size_abi(value), put_abi(value)));
}

template <typename D> Windows::Media::Core::MediaStreamSample consume_Windows_Media_Core_IMediaStreamSampleStatics<D>::CreateFromBuffer(Windows::Storage::Streams::IBuffer const& buffer, Windows::Foundation::TimeSpan const& timestamp) const
{
    Windows::Media::Core::MediaStreamSample value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleStatics)->CreateFromBuffer(get_abi(buffer), get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Core::MediaStreamSample> consume_Windows_Media_Core_IMediaStreamSampleStatics<D>::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, uint32_t count, Windows::Foundation::TimeSpan const& timestamp) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Core::MediaStreamSample> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleStatics)->CreateFromStreamAsync(get_abi(stream), count, get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSample consume_Windows_Media_Core_IMediaStreamSampleStatics2<D>::CreateFromDirect3D11Surface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Foundation::TimeSpan const& timestamp) const
{
    Windows::Media::Core::MediaStreamSample result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSampleStatics2)->CreateFromDirect3D11Surface(get_abi(surface), get_abi(timestamp), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Closed_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceStartingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->add_Starting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Starting_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Starting_revoker>(this, Starting(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->remove_Starting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->add_Paused(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Paused_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Paused_revoker>(this, Paused(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->remove_Paused(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->add_SampleRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SampleRequested_revoker>(this, SampleRequested(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->remove_SampleRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->add_SwitchStreamsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SwitchStreamsRequested_revoker>(this, SwitchStreamsRequested(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->remove_SwitchStreamsRequested(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::NotifyError(Windows::Media::Core::MediaStreamSourceErrorStatus const& errorStatus) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->NotifyError(get_abi(errorStatus)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::AddStreamDescriptor(Windows::Media::Core::IMediaStreamDescriptor const& descriptor) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->AddStreamDescriptor(get_abi(descriptor)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::MediaProtectionManager(Windows::Media::Protection::MediaProtectionManager const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->put_MediaProtectionManager(get_abi(value)));
}

template <typename D> Windows::Media::Protection::MediaProtectionManager consume_Windows_Media_Core_IMediaStreamSource<D>::MediaProtectionManager() const
{
    Windows::Media::Protection::MediaProtectionManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_MediaProtectionManager(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSource<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::CanSeek(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->put_CanSeek(value));
}

template <typename D> bool consume_Windows_Media_Core_IMediaStreamSource<D>::CanSeek() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_CanSeek(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::BufferTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->put_BufferTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSource<D>::BufferTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_BufferTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::SetBufferedRange(Windows::Foundation::TimeSpan const& startOffset, Windows::Foundation::TimeSpan const& endOffset) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->SetBufferedRange(get_abi(startOffset), get_abi(endOffset)));
}

template <typename D> Windows::Storage::FileProperties::MusicProperties consume_Windows_Media_Core_IMediaStreamSource<D>::MusicProperties() const
{
    Windows::Storage::FileProperties::MusicProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_MusicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::VideoProperties consume_Windows_Media_Core_IMediaStreamSource<D>::VideoProperties() const
{
    Windows::Storage::FileProperties::VideoProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_VideoProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_Core_IMediaStreamSource<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource<D>::AddProtectionKey(Windows::Media::Core::IMediaStreamDescriptor const& streamDescriptor, array_view<uint8_t const> keyIdentifier, array_view<uint8_t const> licenseData) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource)->AddProtectionKey(get_abi(streamDescriptor), keyIdentifier.size(), get_abi(keyIdentifier), licenseData.size(), get_abi(licenseData)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource2)->add_SampleRendered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered_revoker consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SampleRendered_revoker>(this, SampleRendered(handler));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMediaStreamSource2)->remove_SampleRendered(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource3<D>::MaxSupportedPlaybackRate(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource3)->put_MaxSupportedPlaybackRate(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Core_IMediaStreamSource3<D>::MaxSupportedPlaybackRate() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource3)->get_MaxSupportedPlaybackRate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSource4<D>::IsLive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource4)->put_IsLive(value));
}

template <typename D> bool consume_Windows_Media_Core_IMediaStreamSource4<D>::IsLive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSource4)->get_IsLive(&value));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceClosedRequest consume_Windows_Media_Core_IMediaStreamSourceClosedEventArgs<D>::Request() const
{
    Windows::Media::Core::MediaStreamSourceClosedRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceClosedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceClosedReason consume_Windows_Media_Core_IMediaStreamSourceClosedRequest<D>::Reason() const
{
    Windows::Media::Core::MediaStreamSourceClosedReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceClosedRequest)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Core_IMediaStreamSourceFactory<D>::CreateFromDescriptor(Windows::Media::Core::IMediaStreamDescriptor const& descriptor) const
{
    Windows::Media::Core::MediaStreamSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceFactory)->CreateFromDescriptor(get_abi(descriptor), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::MediaStreamSource consume_Windows_Media_Core_IMediaStreamSourceFactory<D>::CreateFromDescriptors(Windows::Media::Core::IMediaStreamDescriptor const& descriptor, Windows::Media::Core::IMediaStreamDescriptor const& descriptor2) const
{
    Windows::Media::Core::MediaStreamSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceFactory)->CreateFromDescriptors(get_abi(descriptor), get_abi(descriptor2), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMediaStreamSourceSampleRenderedEventArgs<D>::SampleLag() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs)->get_SampleLag(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::IMediaStreamDescriptor consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::StreamDescriptor() const
{
    Windows::Media::Core::IMediaStreamDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequest)->get_StreamDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceSampleRequestDeferral consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::GetDeferral() const
{
    Windows::Media::Core::MediaStreamSourceSampleRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::Sample(Windows::Media::Core::MediaStreamSample const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequest)->put_Sample(get_abi(value)));
}

template <typename D> Windows::Media::Core::MediaStreamSample consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::Sample() const
{
    Windows::Media::Core::MediaStreamSample value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequest)->get_Sample(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::ReportSampleProgress(uint32_t progress) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequest)->ReportSampleProgress(progress));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceSampleRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral)->Complete());
}

template <typename D> Windows::Media::Core::MediaStreamSourceSampleRequest consume_Windows_Media_Core_IMediaStreamSourceSampleRequestedEventArgs<D>::Request() const
{
    Windows::Media::Core::MediaStreamSourceSampleRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceStartingRequest consume_Windows_Media_Core_IMediaStreamSourceStartingEventArgs<D>::Request() const
{
    Windows::Media::Core::MediaStreamSourceStartingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceStartingEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::StartPosition() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceStartingRequest)->get_StartPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceStartingRequestDeferral consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::GetDeferral() const
{
    Windows::Media::Core::MediaStreamSourceStartingRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceStartingRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::SetActualStartPosition(Windows::Foundation::TimeSpan const& position) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceStartingRequest)->SetActualStartPosition(get_abi(position)));
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceStartingRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral)->Complete());
}

template <typename D> Windows::Media::Core::IMediaStreamDescriptor consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::OldStreamDescriptor() const
{
    Windows::Media::Core::IMediaStreamDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->get_OldStreamDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::IMediaStreamDescriptor consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::NewStreamDescriptor() const
{
    Windows::Media::Core::IMediaStreamDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->get_NewStreamDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::GetDeferral() const
{
    Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral)->Complete());
}

template <typename D> Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequestedEventArgs<D>::Request() const
{
    Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_IMediaTrack<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaTrack)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_IMediaTrack<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaTrack)->get_Language(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaTrackKind consume_Windows_Media_Core_IMediaTrack<D>::TrackKind() const
{
    Windows::Media::Core::MediaTrackKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaTrack)->get_TrackKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMediaTrack<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaTrack)->put_Label(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_IMediaTrack<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMediaTrack)->get_Label(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->add_UpdateStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UpdateStarting_revoker>(this, UpdateStarting(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->remove_UpdateStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->add_UpdateEnded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UpdateEnded_revoker>(this, UpdateEnded(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->remove_UpdateEnded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->add_ErrorOccurred(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->remove_ErrorOccurred(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->add_Aborted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Aborted_revoker>(this, Aborted(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->remove_Aborted(get_abi(token)));
}

template <typename D> Windows::Media::Core::MseAppendMode consume_Windows_Media_Core_IMseSourceBuffer<D>::Mode() const
{
    Windows::Media::Core::MseAppendMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::Mode(Windows::Media::Core::MseAppendMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Core_IMseSourceBuffer<D>::IsUpdating() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_IsUpdating(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseTimeRange> consume_Windows_Media_Core_IMseSourceBuffer<D>::Buffered() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseTimeRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_Buffered(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMseSourceBuffer<D>::TimestampOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_TimestampOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::TimestampOffset(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->put_TimestampOffset(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowStart() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_AppendWindowStart(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowStart(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->put_AppendWindowStart(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowEnd() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->get_AppendWindowEnd(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowEnd(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->put_AppendWindowEnd(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->AppendBuffer(get_abi(buffer)));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendStream(Windows::Storage::Streams::IInputStream const& stream) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->AppendStream(get_abi(stream)));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendStream(Windows::Storage::Streams::IInputStream const& stream, uint64_t maxSize) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->AppendStreamMaxSize(get_abi(stream), maxSize));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::Abort() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->Abort());
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBuffer<D>::Remove(Windows::Foundation::TimeSpan const& start, optional<Windows::Foundation::TimeSpan> const& end) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBuffer)->Remove(get_abi(start), get_abi(end)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBufferList)->add_SourceBufferAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded_revoker consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SourceBufferAdded_revoker>(this, SourceBufferAdded(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBufferList)->remove_SourceBufferAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBufferList)->add_SourceBufferRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved_revoker consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SourceBufferRemoved_revoker>(this, SourceBufferRemoved(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseSourceBufferList)->remove_SourceBufferRemoved(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseSourceBuffer> consume_Windows_Media_Core_IMseSourceBufferList<D>::Buffers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseSourceBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseSourceBufferList)->get_Buffers(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseStreamSource<D>::Opened(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->add_Opened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Opened_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Opened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::Opened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->remove_Opened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseStreamSource<D>::Ended(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->add_Ended(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Ended_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Ended(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Ended_revoker>(this, Ended(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::Ended(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->remove_Ended(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IMseStreamSource<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Closed_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->remove_Closed(get_abi(token)));
}

template <typename D> Windows::Media::Core::MseSourceBufferList consume_Windows_Media_Core_IMseStreamSource<D>::SourceBuffers() const
{
    Windows::Media::Core::MseSourceBufferList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->get_SourceBuffers(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MseSourceBufferList consume_Windows_Media_Core_IMseStreamSource<D>::ActiveSourceBuffers() const
{
    Windows::Media::Core::MseSourceBufferList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->get_ActiveSourceBuffers(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MseReadyState consume_Windows_Media_Core_IMseStreamSource<D>::ReadyState() const
{
    Windows::Media::Core::MseReadyState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->get_ReadyState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Core_IMseStreamSource<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::Duration(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->put_Duration(get_abi(value)));
}

template <typename D> Windows::Media::Core::MseSourceBuffer consume_Windows_Media_Core_IMseStreamSource<D>::AddSourceBuffer(param::hstring const& mimeType) const
{
    Windows::Media::Core::MseSourceBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->AddSourceBuffer(get_abi(mimeType), put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::RemoveSourceBuffer(Windows::Media::Core::MseSourceBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->RemoveSourceBuffer(get_abi(buffer)));
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource<D>::EndOfStream(Windows::Media::Core::MseEndOfStreamStatus const& status) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource)->EndOfStream(get_abi(status)));
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange> consume_Windows_Media_Core_IMseStreamSource2<D>::LiveSeekableRange() const
{
    Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource2)->get_LiveSeekableRange(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_IMseStreamSource2<D>::LiveSeekableRange(optional<Windows::Media::Core::MseTimeRange> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSource2)->put_LiveSeekableRange(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Core_IMseStreamSourceStatics<D>::IsContentTypeSupported(param::hstring const& contentType) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IMseStreamSourceStatics)->IsContentTypeSupported(get_abi(contentType), &value));
    return value;
}

template <typename D> Windows::Media::Core::HighDynamicRangeControl consume_Windows_Media_Core_ISceneAnalysisEffect<D>::HighDynamicRangeAnalyzer() const
{
    Windows::Media::Core::HighDynamicRangeControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffect)->get_HighDynamicRangeAnalyzer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ISceneAnalysisEffect<D>::DesiredAnalysisInterval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffect)->put_DesiredAnalysisInterval(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Core_ISceneAnalysisEffect<D>::DesiredAnalysisInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffect)->get_DesiredAnalysisInterval(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::SceneAnalysisEffect, Windows::Media::Core::SceneAnalyzedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffect)->add_SceneAnalyzed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed_revoker consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::SceneAnalysisEffect, Windows::Media::Core::SceneAnalyzedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SceneAnalyzed_revoker>(this, SceneAnalyzed(handler));
}

template <typename D> void consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffect)->remove_SceneAnalyzed(get_abi(cookie)));
}

template <typename D> Windows::Media::Capture::CapturedFrameControlValues consume_Windows_Media_Core_ISceneAnalysisEffectFrame<D>::FrameControlValues() const
{
    Windows::Media::Capture::CapturedFrameControlValues value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffectFrame)->get_FrameControlValues(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::HighDynamicRangeOutput consume_Windows_Media_Core_ISceneAnalysisEffectFrame<D>::HighDynamicRange() const
{
    Windows::Media::Core::HighDynamicRangeOutput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffectFrame)->get_HighDynamicRange(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::SceneAnalysisRecommendation consume_Windows_Media_Core_ISceneAnalysisEffectFrame2<D>::AnalysisRecommendation() const
{
    Windows::Media::Core::SceneAnalysisRecommendation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalysisEffectFrame2)->get_AnalysisRecommendation(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::SceneAnalysisEffectFrame consume_Windows_Media_Core_ISceneAnalyzedEventArgs<D>::ResultFrame() const
{
    Windows::Media::Core::SceneAnalysisEffectFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISceneAnalyzedEventArgs)->get_ResultFrame(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Core::ISingleSelectMediaTrackList, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISingleSelectMediaTrackList)->add_SelectedIndexChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged_revoker consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::ISingleSelectMediaTrackList, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SelectedIndexChanged_revoker>(this, SelectedIndexChanged(handler));
}

template <typename D> void consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ISingleSelectMediaTrackList)->remove_SelectedIndexChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISingleSelectMediaTrackList)->put_SelectedIndex(value));
}

template <typename D> int32_t consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISingleSelectMediaTrackList)->get_SelectedIndex(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ISpeechCue<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ISpeechCue<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->put_Text(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Media_Core_ISpeechCue<D>::StartPositionInInput() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->get_StartPositionInInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ISpeechCue<D>::StartPositionInInput(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->put_StartPositionInInput(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Media_Core_ISpeechCue<D>::EndPositionInInput() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->get_EndPositionInInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ISpeechCue<D>::EndPositionInInput(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ISpeechCue)->put_EndPositionInInput(get_abi(value)));
}

template <typename D> Windows::Media::MediaProperties::TimedMetadataEncodingProperties consume_Windows_Media_Core_ITimedMetadataStreamDescriptor<D>::EncodingProperties() const
{
    Windows::Media::MediaProperties::TimedMetadataEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataStreamDescriptor)->get_EncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedMetadataStreamDescriptor consume_Windows_Media_Core_ITimedMetadataStreamDescriptor<D>::Copy() const
{
    Windows::Media::Core::TimedMetadataStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataStreamDescriptor)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::TimedMetadataStreamDescriptor consume_Windows_Media_Core_ITimedMetadataStreamDescriptorFactory<D>::Create(Windows::Media::MediaProperties::TimedMetadataEncodingProperties const& encodingProperties) const
{
    Windows::Media::Core::TimedMetadataStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataStreamDescriptorFactory)->Create(get_abi(encodingProperties), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->add_CueEntered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CueEntered_revoker>(this, CueEntered(handler));
}

template <typename D> void consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->remove_CueEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->add_CueExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CueExited_revoker>(this, CueExited(handler));
}

template <typename D> void consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->remove_CueExited(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->add_TrackFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TrackFailed_revoker>(this, TrackFailed(handler));
}

template <typename D> void consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->remove_TrackFailed(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue> consume_Windows_Media_Core_ITimedMetadataTrack<D>::Cues() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->get_Cues(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue> consume_Windows_Media_Core_ITimedMetadataTrack<D>::ActiveCues() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->get_ActiveCues(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedMetadataKind consume_Windows_Media_Core_ITimedMetadataTrack<D>::TimedMetadataKind() const
{
    Windows::Media::Core::TimedMetadataKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->get_TimedMetadataKind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ITimedMetadataTrack<D>::DispatchType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->get_DispatchType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedMetadataTrack<D>::AddCue(Windows::Media::Core::IMediaCue const& cue) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->AddCue(get_abi(cue)));
}

template <typename D> void consume_Windows_Media_Core_ITimedMetadataTrack<D>::RemoveCue(Windows::Media::Core::IMediaCue const& cue) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack)->RemoveCue(get_abi(cue)));
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Core_ITimedMetadataTrack2<D>::PlaybackItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack2)->get_PlaybackItem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ITimedMetadataTrack2<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrack2)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedMetadataTrackErrorCode consume_Windows_Media_Core_ITimedMetadataTrackError<D>::ErrorCode() const
{
    Windows::Media::Core::TimedMetadataTrackErrorCode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrackError)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Core_ITimedMetadataTrackError<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrackError)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedMetadataTrack consume_Windows_Media_Core_ITimedMetadataTrackFactory<D>::Create(param::hstring const& id, param::hstring const& language, Windows::Media::Core::TimedMetadataKind const& kind) const
{
    Windows::Media::Core::TimedMetadataTrack value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrackFactory)->Create(get_abi(id), get_abi(language), get_abi(kind), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedMetadataTrackError consume_Windows_Media_Core_ITimedMetadataTrackFailedEventArgs<D>::Error() const
{
    Windows::Media::Core::TimedMetadataTrackError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrackFailedEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack> consume_Windows_Media_Core_ITimedMetadataTrackProvider<D>::TimedMetadataTracks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedMetadataTrackProvider)->get_TimedMetadataTracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextRegion consume_Windows_Media_Core_ITimedTextCue<D>::CueRegion() const
{
    Windows::Media::Core::TimedTextRegion value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextCue)->get_CueRegion(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextCue<D>::CueRegion(Windows::Media::Core::TimedTextRegion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextCue)->put_CueRegion(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextStyle consume_Windows_Media_Core_ITimedTextCue<D>::CueStyle() const
{
    Windows::Media::Core::TimedTextStyle value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextCue)->get_CueStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextCue<D>::CueStyle(Windows::Media::Core::TimedTextStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextCue)->put_CueStyle(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextLine> consume_Windows_Media_Core_ITimedTextCue<D>::Lines() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextLine> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextCue)->get_Lines(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ITimedTextLine<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextLine)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextLine<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextLine)->put_Text(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextSubformat> consume_Windows_Media_Core_ITimedTextLine<D>::Subformats() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextSubformat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextLine)->get_Subformats(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_ITimedTextRegion<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_Name(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextPoint consume_Windows_Media_Core_ITimedTextRegion<D>::Position() const
{
    Windows::Media::Core::TimedTextPoint value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_Position(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::Position(Windows::Media::Core::TimedTextPoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_Position(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextSize consume_Windows_Media_Core_ITimedTextRegion<D>::Extent() const
{
    Windows::Media::Core::TimedTextSize value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_Extent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::Extent(Windows::Media::Core::TimedTextSize const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_Extent(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Media_Core_ITimedTextRegion<D>::Background() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_Background(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::Background(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_Background(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextWritingMode consume_Windows_Media_Core_ITimedTextRegion<D>::WritingMode() const
{
    Windows::Media::Core::TimedTextWritingMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_WritingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::WritingMode(Windows::Media::Core::TimedTextWritingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_WritingMode(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextDisplayAlignment consume_Windows_Media_Core_ITimedTextRegion<D>::DisplayAlignment() const
{
    Windows::Media::Core::TimedTextDisplayAlignment value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_DisplayAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::DisplayAlignment(Windows::Media::Core::TimedTextDisplayAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_DisplayAlignment(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextDouble consume_Windows_Media_Core_ITimedTextRegion<D>::LineHeight() const
{
    Windows::Media::Core::TimedTextDouble value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_LineHeight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::LineHeight(Windows::Media::Core::TimedTextDouble const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_LineHeight(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Core_ITimedTextRegion<D>::IsOverflowClipped() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_IsOverflowClipped(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::IsOverflowClipped(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_IsOverflowClipped(value));
}

template <typename D> Windows::Media::Core::TimedTextPadding consume_Windows_Media_Core_ITimedTextRegion<D>::Padding() const
{
    Windows::Media::Core::TimedTextPadding value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_Padding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::Padding(Windows::Media::Core::TimedTextPadding const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_Padding(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextWrapping consume_Windows_Media_Core_ITimedTextRegion<D>::TextWrapping() const
{
    Windows::Media::Core::TimedTextWrapping value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_TextWrapping(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::TextWrapping(Windows::Media::Core::TimedTextWrapping const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_TextWrapping(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Media_Core_ITimedTextRegion<D>::ZIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_ZIndex(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::ZIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_ZIndex(value));
}

template <typename D> Windows::Media::Core::TimedTextScrollMode consume_Windows_Media_Core_ITimedTextRegion<D>::ScrollMode() const
{
    Windows::Media::Core::TimedTextScrollMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->get_ScrollMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextRegion<D>::ScrollMode(Windows::Media::Core::TimedTextScrollMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextRegion)->put_ScrollMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedTextSource, Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSource)->add_Resolved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_ITimedTextSource<D>::Resolved_revoker consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedTextSource, Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Resolved_revoker>(this, Resolved(handler));
}

template <typename D> void consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::ITimedTextSource)->remove_Resolved(get_abi(token)));
}

template <typename D> Windows::Media::Core::TimedMetadataTrackError consume_Windows_Media_Core_ITimedTextSourceResolveResultEventArgs<D>::Error() const
{
    Windows::Media::Core::TimedMetadataTrackError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceResolveResultEventArgs)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack> consume_Windows_Media_Core_ITimedTextSourceResolveResultEventArgs<D>::Tracks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceResolveResultEventArgs)->get_Tracks(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Media::Core::TimedTextSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics)->CreateFromStream(get_abi(stream), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromUri(Windows::Foundation::Uri const& uri) const
{
    Windows::Media::Core::TimedTextSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics)->CreateFromUri(get_abi(uri), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& defaultLanguage) const
{
    Windows::Media::Core::TimedTextSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics)->CreateFromStreamWithLanguage(get_abi(stream), get_abi(defaultLanguage), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromUri(Windows::Foundation::Uri const& uri, param::hstring const& defaultLanguage) const
{
    Windows::Media::Core::TimedTextSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics)->CreateFromUriWithLanguage(get_abi(uri), get_abi(defaultLanguage), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromStreamWithIndex(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Storage::Streams::IRandomAccessStream const& indexStream) const
{
    Windows::Media::Core::TimedTextSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromStreamWithIndex(get_abi(stream), get_abi(indexStream), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromUriWithIndex(Windows::Foundation::Uri const& uri, Windows::Foundation::Uri const& indexUri) const
{
    Windows::Media::Core::TimedTextSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromUriWithIndex(get_abi(uri), get_abi(indexUri), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromStreamWithIndex(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Storage::Streams::IRandomAccessStream const& indexStream, param::hstring const& defaultLanguage) const
{
    Windows::Media::Core::TimedTextSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromStreamWithIndexAndLanguage(get_abi(stream), get_abi(indexStream), get_abi(defaultLanguage), put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::TimedTextSource consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromUriWithIndex(Windows::Foundation::Uri const& uri, Windows::Foundation::Uri const& indexUri, param::hstring const& defaultLanguage) const
{
    Windows::Media::Core::TimedTextSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromUriWithIndexAndLanguage(get_abi(uri), get_abi(indexUri), get_abi(defaultLanguage), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Media_Core_ITimedTextStyle<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Core_ITimedTextStyle<D>::FontFamily() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_FontFamily(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::FontFamily(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_FontFamily(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextDouble consume_Windows_Media_Core_ITimedTextStyle<D>::FontSize() const
{
    Windows::Media::Core::TimedTextDouble value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_FontSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::FontSize(Windows::Media::Core::TimedTextDouble const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_FontSize(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextWeight consume_Windows_Media_Core_ITimedTextStyle<D>::FontWeight() const
{
    Windows::Media::Core::TimedTextWeight value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_FontWeight(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::FontWeight(Windows::Media::Core::TimedTextWeight const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_FontWeight(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Media_Core_ITimedTextStyle<D>::Foreground() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_Foreground(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::Foreground(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_Foreground(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Media_Core_ITimedTextStyle<D>::Background() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_Background(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::Background(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_Background(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Core_ITimedTextStyle<D>::IsBackgroundAlwaysShown() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_IsBackgroundAlwaysShown(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::IsBackgroundAlwaysShown(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_IsBackgroundAlwaysShown(value));
}

template <typename D> Windows::Media::Core::TimedTextFlowDirection consume_Windows_Media_Core_ITimedTextStyle<D>::FlowDirection() const
{
    Windows::Media::Core::TimedTextFlowDirection value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_FlowDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::FlowDirection(Windows::Media::Core::TimedTextFlowDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_FlowDirection(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextLineAlignment consume_Windows_Media_Core_ITimedTextStyle<D>::LineAlignment() const
{
    Windows::Media::Core::TimedTextLineAlignment value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_LineAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::LineAlignment(Windows::Media::Core::TimedTextLineAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_LineAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_OutlineColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_OutlineColor(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextDouble consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineThickness() const
{
    Windows::Media::Core::TimedTextDouble value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_OutlineThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineThickness(Windows::Media::Core::TimedTextDouble const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_OutlineThickness(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextDouble consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineRadius() const
{
    Windows::Media::Core::TimedTextDouble value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->get_OutlineRadius(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineRadius(Windows::Media::Core::TimedTextDouble const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle)->put_OutlineRadius(get_abi(value)));
}

template <typename D> Windows::Media::Core::TimedTextFontStyle consume_Windows_Media_Core_ITimedTextStyle2<D>::FontStyle() const
{
    Windows::Media::Core::TimedTextFontStyle value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->get_FontStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle2<D>::FontStyle(Windows::Media::Core::TimedTextFontStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->put_FontStyle(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Core_ITimedTextStyle2<D>::IsUnderlineEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->get_IsUnderlineEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle2<D>::IsUnderlineEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->put_IsUnderlineEnabled(value));
}

template <typename D> bool consume_Windows_Media_Core_ITimedTextStyle2<D>::IsLineThroughEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->get_IsLineThroughEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle2<D>::IsLineThroughEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->put_IsLineThroughEnabled(value));
}

template <typename D> bool consume_Windows_Media_Core_ITimedTextStyle2<D>::IsOverlineEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->get_IsOverlineEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextStyle2<D>::IsOverlineEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextStyle2)->put_IsOverlineEnabled(value));
}

template <typename D> int32_t consume_Windows_Media_Core_ITimedTextSubformat<D>::StartIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->get_StartIndex(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextSubformat<D>::StartIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->put_StartIndex(value));
}

template <typename D> int32_t consume_Windows_Media_Core_ITimedTextSubformat<D>::Length() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->get_Length(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextSubformat<D>::Length(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->put_Length(value));
}

template <typename D> Windows::Media::Core::TimedTextStyle consume_Windows_Media_Core_ITimedTextSubformat<D>::SubformatStyle() const
{
    Windows::Media::Core::TimedTextStyle value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->get_SubformatStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Core_ITimedTextSubformat<D>::SubformatStyle(Windows::Media::Core::TimedTextStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::ITimedTextSubformat)->put_SubformatStyle(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Core_IVideoStabilizationEffect<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffect)->put_Enabled(value));
}

template <typename D> bool consume_Windows_Media_Core_IVideoStabilizationEffect<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffect)->get_Enabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoStabilizationEffect, Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffect)->add_EnabledChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged_revoker consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoStabilizationEffect, Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EnabledChanged_revoker>(this, EnabledChanged(handler));
}

template <typename D> void consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffect)->remove_EnabledChanged(get_abi(cookie)));
}

template <typename D> Windows::Media::Capture::VideoStreamConfiguration consume_Windows_Media_Core_IVideoStabilizationEffect<D>::GetRecommendedStreamConfiguration(Windows::Media::Devices::VideoDeviceController const& controller, Windows::Media::MediaProperties::VideoEncodingProperties const& desiredProperties) const
{
    Windows::Media::Capture::VideoStreamConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffect)->GetRecommendedStreamConfiguration(get_abi(controller), get_abi(desiredProperties), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason consume_Windows_Media_Core_IVideoStabilizationEffectEnabledChangedEventArgs<D>::Reason() const
{
    Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_Core_IVideoStreamDescriptor<D>::EncodingProperties() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties encodingProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStreamDescriptor)->get_EncodingProperties(put_abi(encodingProperties)));
    return encodingProperties;
}

template <typename D> Windows::Media::Core::VideoStreamDescriptor consume_Windows_Media_Core_IVideoStreamDescriptor2<D>::Copy() const
{
    Windows::Media::Core::VideoStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStreamDescriptor2)->Copy(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Core::VideoStreamDescriptor consume_Windows_Media_Core_IVideoStreamDescriptorFactory<D>::Create(Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties) const
{
    Windows::Media::Core::VideoStreamDescriptor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoStreamDescriptorFactory)->Create(get_abi(encodingProperties), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoTrack, Windows::Media::Core::VideoTrackOpenFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrack)->add_OpenFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed_revoker consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoTrack, Windows::Media::Core::VideoTrackOpenFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
}

template <typename D> void consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Core::IVideoTrack)->remove_OpenFailed(get_abi(token)));
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_Core_IVideoTrack<D>::GetEncodingProperties() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrack)->GetEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Playback::MediaPlaybackItem consume_Windows_Media_Core_IVideoTrack<D>::PlaybackItem() const
{
    Windows::Media::Playback::MediaPlaybackItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrack)->get_PlaybackItem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Core_IVideoTrack<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrack)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::VideoTrackSupportInfo consume_Windows_Media_Core_IVideoTrack<D>::SupportInfo() const
{
    Windows::Media::Core::VideoTrackSupportInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrack)->get_SupportInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Media_Core_IVideoTrackOpenFailedEventArgs<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrackOpenFailedEventArgs)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaDecoderStatus consume_Windows_Media_Core_IVideoTrackSupportInfo<D>::DecoderStatus() const
{
    Windows::Media::Core::MediaDecoderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrackSupportInfo)->get_DecoderStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Core::MediaSourceStatus consume_Windows_Media_Core_IVideoTrackSupportInfo<D>::MediaSourceStatus() const
{
    Windows::Media::Core::MediaSourceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Core::IVideoTrackSupportInfo)->get_MediaSourceStatus(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Core::IAudioStreamDescriptor> : produce_base<D, Windows::Media::Core::IAudioStreamDescriptor>
{
    int32_t WINRT_CALL get_EncodingProperties(void** encodingProperties) noexcept final
    {
        try
        {
            *encodingProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *encodingProperties = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IAudioStreamDescriptor2> : produce_base<D, Windows::Media::Core::IAudioStreamDescriptor2>
{
    int32_t WINRT_CALL put_LeadingEncoderPadding(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeadingEncoderPadding, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().LeadingEncoderPadding(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeadingEncoderPadding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeadingEncoderPadding, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().LeadingEncoderPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrailingEncoderPadding(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrailingEncoderPadding, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().TrailingEncoderPadding(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrailingEncoderPadding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrailingEncoderPadding, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().TrailingEncoderPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IAudioStreamDescriptor3> : produce_base<D, Windows::Media::Core::IAudioStreamDescriptor3>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::Core::AudioStreamDescriptor));
            *result = detach_from<Windows::Media::Core::AudioStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IAudioStreamDescriptorFactory> : produce_base<D, Windows::Media::Core::IAudioStreamDescriptorFactory>
{
    int32_t WINRT_CALL Create(void* encodingProperties, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Core::AudioStreamDescriptor), Windows::Media::MediaProperties::AudioEncodingProperties const&);
            *result = detach_from<Windows::Media::Core::AudioStreamDescriptor>(this->shim().Create(*reinterpret_cast<Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IAudioTrack> : produce_base<D, Windows::Media::Core::IAudioTrack>
{
    int32_t WINRT_CALL add_OpenFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::AudioTrack, Windows::Media::Core::AudioTrackOpenFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::AudioTrack, Windows::Media::Core::AudioTrackOpenFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OpenFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().GetEncodingProperties());
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

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportInfo, WINRT_WRAP(Windows::Media::Core::AudioTrackSupportInfo));
            *value = detach_from<Windows::Media::Core::AudioTrackSupportInfo>(this->shim().SupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IAudioTrackOpenFailedEventArgs> : produce_base<D, Windows::Media::Core::IAudioTrackOpenFailedEventArgs>
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
struct produce<D, Windows::Media::Core::IAudioTrackSupportInfo> : produce_base<D, Windows::Media::Core::IAudioTrackSupportInfo>
{
    int32_t WINRT_CALL get_DecoderStatus(Windows::Media::Core::MediaDecoderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecoderStatus, WINRT_WRAP(Windows::Media::Core::MediaDecoderStatus));
            *value = detach_from<Windows::Media::Core::MediaDecoderStatus>(this->shim().DecoderStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Degradation(Windows::Media::Core::AudioDecoderDegradation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Degradation, WINRT_WRAP(Windows::Media::Core::AudioDecoderDegradation));
            *value = detach_from<Windows::Media::Core::AudioDecoderDegradation>(this->shim().Degradation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DegradationReason(Windows::Media::Core::AudioDecoderDegradationReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DegradationReason, WINRT_WRAP(Windows::Media::Core::AudioDecoderDegradationReason));
            *value = detach_from<Windows::Media::Core::AudioDecoderDegradationReason>(this->shim().DegradationReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaSourceStatus(Windows::Media::Core::MediaSourceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaSourceStatus, WINRT_WRAP(Windows::Media::Core::MediaSourceStatus));
            *value = detach_from<Windows::Media::Core::MediaSourceStatus>(this->shim().MediaSourceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IChapterCue> : produce_base<D, Windows::Media::Core::IChapterCue>
{
    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::Media::Core::ICodecInfo> : produce_base<D, Windows::Media::Core::ICodecInfo>
{
    int32_t WINRT_CALL get_Kind(Windows::Media::Core::CodecKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Media::Core::CodecKind));
            *value = detach_from<Windows::Media::Core::CodecKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Category(Windows::Media::Core::CodecCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(Windows::Media::Core::CodecCategory));
            *value = detach_from<Windows::Media::Core::CodecCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtypes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Subtypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrusted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrusted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrusted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ICodecQuery> : produce_base<D, Windows::Media::Core::ICodecQuery>
{
    int32_t WINRT_CALL FindAllAsync(Windows::Media::Core::CodecKind kind, Windows::Media::Core::CodecCategory category, void* subType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::CodecInfo>>), Windows::Media::Core::CodecKind const, Windows::Media::Core::CodecCategory const, hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::CodecInfo>>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::Media::Core::CodecKind const*>(&kind), *reinterpret_cast<Windows::Media::Core::CodecCategory const*>(&category), *reinterpret_cast<hstring const*>(&subType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ICodecSubtypesStatics> : produce_base<D, Windows::Media::Core::ICodecSubtypesStatics>
{
    int32_t WINRT_CALL get_VideoFormatDV25(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDV25, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDV25());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDV50(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDV50, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDV50());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDvc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDvc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDvc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDvh1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDvh1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDvh1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDvhD(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDvhD, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDvhD());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDvsd(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDvsd, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDvsd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatDvsl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatDvsl, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatDvsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatH263(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatH263, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatH263());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatH264(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatH264, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatH264());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatH265(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatH265, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatH265());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatH264ES(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatH264ES, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatH264ES());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatHevc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatHevc, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatHevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatHevcES(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatHevcES, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatHevcES());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatM4S2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatM4S2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatM4S2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMjpg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMjpg, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMjpg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMP43(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMP43, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMP43());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMP4S(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMP4S, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMP4S());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMP4V(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMP4V, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMP4V());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMpeg2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMpeg2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatVP80(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatVP80, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatVP80());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatVP90(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatVP90, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatVP90());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMpg1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMpg1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMpg1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMss1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMss1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMss1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatMss2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatMss2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatMss2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatWmv1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatWmv1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatWmv1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatWmv2(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatWmv2, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatWmv2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatWmv3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatWmv3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatWmv3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormatWvc1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormatWvc1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormatWvc1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormat420O(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormat420O, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoFormat420O());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAdts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAdts, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAdts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAlac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAlac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAlac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAmrNB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAmrNB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAmrNB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAmrWB(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAmrWB, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAmrWB());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatAmrWP(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatAmrWP, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatAmrWP());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatDolbyAC3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatDolbyAC3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyAC3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatDolbyAC3Spdif(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatDolbyAC3Spdif, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyAC3Spdif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatDolbyDDPlus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatDolbyDDPlus, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyDDPlus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatDrm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatDrm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatDrm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatDts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatDts, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatDts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatFlac(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatFlac, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatFlac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatFloat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatFloat, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatFloat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatMP3(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatMP3, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatMP3());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatMPeg(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatMPeg, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatMPeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatMsp1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatMsp1, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatMsp1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatOpus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatOpus, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatOpus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatPcm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatPcm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatPcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatWmaSpdif(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatWmaSpdif, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatWmaSpdif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatWMAudioLossless(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatWMAudioLossless, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioLossless());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatWMAudioV8(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatWMAudioV8, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioV8());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFormatWMAudioV9(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFormatWMAudioV9, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioV9());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IDataCue> : produce_base<D, Windows::Media::Core::IDataCue>
{
    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IDataCue2> : produce_base<D, Windows::Media::Core::IDataCue2>
{
    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::PropertySet));
            *value = detach_from<Windows::Foundation::Collections::PropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IFaceDetectedEventArgs> : produce_base<D, Windows::Media::Core::IFaceDetectedEventArgs>
{
    int32_t WINRT_CALL get_ResultFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultFrame, WINRT_WRAP(Windows::Media::Core::FaceDetectionEffectFrame));
            *value = detach_from<Windows::Media::Core::FaceDetectionEffectFrame>(this->shim().ResultFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IFaceDetectionEffect> : produce_base<D, Windows::Media::Core::IFaceDetectionEffect>
{
    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredDetectionInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDetectionInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DesiredDetectionInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredDetectionInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDetectionInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DesiredDetectionInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FaceDetected(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FaceDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::FaceDetectionEffect, Windows::Media::Core::FaceDetectedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().FaceDetected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::FaceDetectionEffect, Windows::Media::Core::FaceDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FaceDetected(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FaceDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FaceDetected(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IFaceDetectionEffectDefinition> : produce_base<D, Windows::Media::Core::IFaceDetectionEffectDefinition>
{
    int32_t WINRT_CALL put_DetectionMode(Windows::Media::Core::FaceDetectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetectionMode, WINRT_WRAP(void), Windows::Media::Core::FaceDetectionMode const&);
            this->shim().DetectionMode(*reinterpret_cast<Windows::Media::Core::FaceDetectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DetectionMode(Windows::Media::Core::FaceDetectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetectionMode, WINRT_WRAP(Windows::Media::Core::FaceDetectionMode));
            *value = detach_from<Windows::Media::Core::FaceDetectionMode>(this->shim().DetectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SynchronousDetectionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SynchronousDetectionEnabled, WINRT_WRAP(void), bool);
            this->shim().SynchronousDetectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SynchronousDetectionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SynchronousDetectionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SynchronousDetectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IFaceDetectionEffectFrame> : produce_base<D, Windows::Media::Core::IFaceDetectionEffectFrame>
{
    int32_t WINRT_CALL get_DetectedFaces(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetectedFaces, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::FaceAnalysis::DetectedFace>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::FaceAnalysis::DetectedFace>>(this->shim().DetectedFaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IHighDynamicRangeControl> : produce_base<D, Windows::Media::Core::IHighDynamicRangeControl>
{
    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IHighDynamicRangeOutput> : produce_base<D, Windows::Media::Core::IHighDynamicRangeOutput>
{
    int32_t WINRT_CALL get_Certainty(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Certainty, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Certainty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameControllers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameControllers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::Core::FrameController>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Devices::Core::FrameController>>(this->shim().FrameControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IImageCue> : produce_base<D, Windows::Media::Core::IImageCue>
{
    int32_t WINRT_CALL get_Position(struct struct_Windows_Media_Core_TimedTextPoint* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Media::Core::TimedTextPoint));
            *value = detach_from<Windows::Media::Core::TimedTextPoint>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(struct struct_Windows_Media_Core_TimedTextPoint value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Media::Core::TimedTextPoint const&);
            this->shim().Position(*reinterpret_cast<Windows::Media::Core::TimedTextPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extent(struct struct_Windows_Media_Core_TimedTextSize* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extent, WINRT_WRAP(Windows::Media::Core::TimedTextSize));
            *value = detach_from<Windows::Media::Core::TimedTextSize>(this->shim().Extent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Extent(struct struct_Windows_Media_Core_TimedTextSize value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extent, WINRT_WRAP(void), Windows::Media::Core::TimedTextSize const&);
            this->shim().Extent(*reinterpret_cast<Windows::Media::Core::TimedTextSize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SoftwareBitmap(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().SoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoftwareBitmap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareBitmap, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap));
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs> : produce_base<D, Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Media::Core::MediaStreamSource));
            *value = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RandomAccessStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RandomAccessStream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().RandomAccessStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ILowLightFusionResult> : produce_base<D, Windows::Media::Core::ILowLightFusionResult>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap));
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ILowLightFusionStatics> : produce_base<D, Windows::Media::Core::ILowLightFusionStatics>
{
    int32_t WINRT_CALL get_SupportedBitmapPixelFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedBitmapPixelFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapPixelFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapPixelFormat>>(this->shim().SupportedBitmapPixelFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSupportedFrameCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSupportedFrameCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxSupportedFrameCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FuseAsync(void* frameSet, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FuseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Core::LowLightFusionResult, double>), Windows::Foundation::Collections::IIterable<Windows::Graphics::Imaging::SoftwareBitmap> const);
            *result = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Core::LowLightFusionResult, double>>(this->shim().FuseAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Graphics::Imaging::SoftwareBitmap> const*>(&frameSet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaBinder> : produce_base<D, Windows::Media::Core::IMediaBinder>
{
    int32_t WINRT_CALL add_Binding(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Binding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBinder, Windows::Media::Core::MediaBindingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Binding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBinder, Windows::Media::Core::MediaBindingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Binding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Binding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Binding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Token(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Token(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(void), hstring const&);
            this->shim().Token(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
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
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaBindingEventArgs> : produce_base<D, Windows::Media::Core::IMediaBindingEventArgs>
{
    int32_t WINRT_CALL add_Canceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBindingEventArgs, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Canceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaBindingEventArgs, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Canceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Canceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_MediaBinder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaBinder, WINRT_WRAP(Windows::Media::Core::MediaBinder));
            *value = detach_from<Windows::Media::Core::MediaBinder>(this->shim().MediaBinder());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *deferral = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetUri(void* uri) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SetUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStream(void* stream, void* contentType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStream, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&, hstring const&);
            this->shim().SetStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&contentType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStreamReference(void* stream, void* contentType) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStreamReference, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&, hstring const&);
            this->shim().SetStreamReference(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream), *reinterpret_cast<hstring const*>(&contentType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaBindingEventArgs2> : produce_base<D, Windows::Media::Core::IMediaBindingEventArgs2>
{
    int32_t WINRT_CALL SetAdaptiveMediaSource(void* mediaSource) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAdaptiveMediaSource, WINRT_WRAP(void), Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const&);
            this->shim().SetAdaptiveMediaSource(*reinterpret_cast<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const*>(&mediaSource));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStorageFile(void* file) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStorageFile, WINRT_WRAP(void), Windows::Storage::IStorageFile const&);
            this->shim().SetStorageFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaBindingEventArgs3> : produce_base<D, Windows::Media::Core::IMediaBindingEventArgs3>
{
    int32_t WINRT_CALL SetDownloadOperation(void* downloadOperation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDownloadOperation, WINRT_WRAP(void), Windows::Networking::BackgroundTransfer::DownloadOperation const&);
            this->shim().SetDownloadOperation(*reinterpret_cast<Windows::Networking::BackgroundTransfer::DownloadOperation const*>(&downloadOperation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaCue> : produce_base<D, Windows::Media::Core::IMediaCue>
{
    int32_t WINRT_CALL put_StartTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().StartTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
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

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaCueEventArgs> : produce_base<D, Windows::Media::Core::IMediaCueEventArgs>
{
    int32_t WINRT_CALL get_Cue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cue, WINRT_WRAP(Windows::Media::Core::IMediaCue));
            *value = detach_from<Windows::Media::Core::IMediaCue>(this->shim().Cue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSource> : produce_base<D, Windows::Media::Core::IMediaSource>
{};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSource2> : produce_base<D, Windows::Media::Core::IMediaSource2>
{
    int32_t WINRT_CALL add_OpenOperationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenOperationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OpenOperationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OpenOperationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OpenOperationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OpenOperationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
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

    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExternalTimedTextSources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExternalTimedTextSources, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedTextSource>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedTextSource>>(this->shim().ExternalTimedTextSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExternalTimedMetadataTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExternalTimedMetadataTracks, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedMetadataTrack>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Media::Core::TimedMetadataTrack>>(this->shim().ExternalTimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSource3> : produce_base<D, Windows::Media::Core::IMediaSource3>
{
    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSource, Windows::Media::Core::MediaSourceStateChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL get_State(Windows::Media::Core::MediaSourceState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Core::MediaSourceState));
            *value = detach_from<Windows::Media::Core::MediaSourceState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void));
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSource4> : produce_base<D, Windows::Media::Core::IMediaSource4>
{
    int32_t WINRT_CALL get_AdaptiveMediaSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdaptiveMediaSource, WINRT_WRAP(Windows::Media::Streaming::Adaptive::AdaptiveMediaSource));
            *value = detach_from<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>(this->shim().AdaptiveMediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaStreamSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaStreamSource));
            *value = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().MediaStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MseStreamSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MseStreamSource, WINRT_WRAP(Windows::Media::Core::MseStreamSource));
            *value = detach_from<Windows::Media::Core::MseStreamSource>(this->shim().MseStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().OpenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSource5> : produce_base<D, Windows::Media::Core::IMediaSource5>
{
    int32_t WINRT_CALL get_DownloadOperation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadOperation, WINRT_WRAP(Windows::Networking::BackgroundTransfer::DownloadOperation));
            *value = detach_from<Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().DownloadOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceAppServiceConnection> : produce_base<D, Windows::Media::Core::IMediaSourceAppServiceConnection>
{
    int32_t WINRT_CALL add_InitializeMediaStreamSourceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeMediaStreamSourceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSourceAppServiceConnection, Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InitializeMediaStreamSourceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaSourceAppServiceConnection, Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InitializeMediaStreamSourceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InitializeMediaStreamSourceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InitializeMediaStreamSourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceAppServiceConnectionFactory> : produce_base<D, Windows::Media::Core::IMediaSourceAppServiceConnectionFactory>
{
    int32_t WINRT_CALL Create(void* appServiceConnection, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Core::MediaSourceAppServiceConnection), Windows::ApplicationModel::AppService::AppServiceConnection const&);
            *result = detach_from<Windows::Media::Core::MediaSourceAppServiceConnection>(this->shim().Create(*reinterpret_cast<Windows::ApplicationModel::AppService::AppServiceConnection const*>(&appServiceConnection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceError> : produce_base<D, Windows::Media::Core::IMediaSourceError>
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
struct produce<D, Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs> : produce_base<D, Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs>
{
    int32_t WINRT_CALL get_Error(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Media::Core::MediaSourceError));
            *value = detach_from<Windows::Media::Core::MediaSourceError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceStateChangedEventArgs> : produce_base<D, Windows::Media::Core::IMediaSourceStateChangedEventArgs>
{
    int32_t WINRT_CALL get_OldState(Windows::Media::Core::MediaSourceState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldState, WINRT_WRAP(Windows::Media::Core::MediaSourceState));
            *value = detach_from<Windows::Media::Core::MediaSourceState>(this->shim().OldState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewState(Windows::Media::Core::MediaSourceState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewState, WINRT_WRAP(Windows::Media::Core::MediaSourceState));
            *value = detach_from<Windows::Media::Core::MediaSourceState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceStatics> : produce_base<D, Windows::Media::Core::IMediaSourceStatics>
{
    int32_t WINRT_CALL CreateFromAdaptiveMediaSource(void* mediaSource, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromAdaptiveMediaSource, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromAdaptiveMediaSource(*reinterpret_cast<Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromMediaStreamSource(void* mediaSource, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMediaStreamSource, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Core::MediaStreamSource const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaStreamSource(*reinterpret_cast<Windows::Media::Core::MediaStreamSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromMseStreamSource(void* mediaSource, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMseStreamSource, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Core::MseStreamSource const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromMseStreamSource(*reinterpret_cast<Windows::Media::Core::MseStreamSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIMediaSource(void* mediaSource, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIMediaSource, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Core::IMediaSource const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromIMediaSource(*reinterpret_cast<Windows::Media::Core::IMediaSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStorageFile(void* file, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStorageFile, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Storage::IStorageFile const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromStorageFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStream(void* stream, void* contentType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStream, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Storage::Streams::IRandomAccessStream const&, hstring const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamReference(void* stream, void* contentType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamReference, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Storage::Streams::IRandomAccessStreamReference const&, hstring const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromStreamReference(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream), *reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUri(void* uri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUri, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Foundation::Uri const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceStatics2> : produce_base<D, Windows::Media::Core::IMediaSourceStatics2>
{
    int32_t WINRT_CALL CreateFromMediaBinder(void* binder, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMediaBinder, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Core::MediaBinder const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaBinder(*reinterpret_cast<Windows::Media::Core::MediaBinder const*>(&binder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceStatics3> : produce_base<D, Windows::Media::Core::IMediaSourceStatics3>
{
    int32_t WINRT_CALL CreateFromMediaFrameSource(void* frameSource, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMediaFrameSource, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Media::Capture::Frames::MediaFrameSource const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaFrameSource(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameSource const*>(&frameSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaSourceStatics4> : produce_base<D, Windows::Media::Core::IMediaSourceStatics4>
{
    int32_t WINRT_CALL CreateFromDownloadOperation(void* downloadOperation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDownloadOperation, WINRT_WRAP(Windows::Media::Core::MediaSource), Windows::Networking::BackgroundTransfer::DownloadOperation const&);
            *result = detach_from<Windows::Media::Core::MediaSource>(this->shim().CreateFromDownloadOperation(*reinterpret_cast<Windows::Networking::BackgroundTransfer::DownloadOperation const*>(&downloadOperation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamDescriptor> : produce_base<D, Windows::Media::Core::IMediaStreamDescriptor>
{
    int32_t WINRT_CALL get_IsSelected(bool* selected) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(bool));
            *selected = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamDescriptor2> : produce_base<D, Windows::Media::Core::IMediaStreamDescriptor2>
{
    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSample> : produce_base<D, Windows::Media::Core::IMediaStreamSample>
{
    int32_t WINRT_CALL add_Processed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Processed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSample, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Processed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSample, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Processed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Processed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Processed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Buffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffer, WINRT_WRAP(Windows::Storage::Streams::Buffer));
            *value = detach_from<Windows::Storage::Streams::Buffer>(this->shim().Buffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedProperties, WINRT_WRAP(Windows::Media::Core::MediaStreamSamplePropertySet));
            *value = detach_from<Windows::Media::Core::MediaStreamSamplePropertySet>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Protection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Protection, WINRT_WRAP(Windows::Media::Core::MediaStreamSampleProtectionProperties));
            *value = detach_from<Windows::Media::Core::MediaStreamSampleProtectionProperties>(this->shim().Protection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodeTimestamp(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeTimestamp, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DecodeTimestamp(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodeTimestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodeTimestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DecodeTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_KeyFrame(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrame, WINRT_WRAP(void), bool);
            this->shim().KeyFrame(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyFrame(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrame, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().KeyFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Discontinuous(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Discontinuous, WINRT_WRAP(void), bool);
            this->shim().Discontinuous(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Discontinuous(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Discontinuous, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Discontinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSample2> : produce_base<D, Windows::Media::Core::IMediaStreamSample2>
{
    int32_t WINRT_CALL get_Direct3D11Surface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3D11Surface, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3D11Surface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSampleProtectionProperties> : produce_base<D, Windows::Media::Core::IMediaStreamSampleProtectionProperties>
{
    int32_t WINRT_CALL SetKeyIdentifier(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetKeyIdentifier, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetKeyIdentifier(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetKeyIdentifier(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetKeyIdentifier, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetKeyIdentifier(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInitializationVector(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInitializationVector, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetInitializationVector(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInitializationVector(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInitializationVector, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetInitializationVector(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSubSampleMapping(uint32_t __valueSize, uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSubSampleMapping, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().SetSubSampleMapping(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSubSampleMapping(uint32_t* __valueSize, uint8_t** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSubSampleMapping, WINRT_WRAP(void), com_array<uint8_t>&);
            this->shim().GetSubSampleMapping(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSampleStatics> : produce_base<D, Windows::Media::Core::IMediaStreamSampleStatics>
{
    int32_t WINRT_CALL CreateFromBuffer(void* buffer, Windows::Foundation::TimeSpan timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::Media::Core::MediaStreamSample), Windows::Storage::Streams::IBuffer const&, Windows::Foundation::TimeSpan const&);
            *value = detach_from<Windows::Media::Core::MediaStreamSample>(this->shim().CreateFromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamAsync(void* stream, uint32_t count, Windows::Foundation::TimeSpan timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Core::MediaStreamSample>), Windows::Storage::Streams::IInputStream const, uint32_t, Windows::Foundation::TimeSpan const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Core::MediaStreamSample>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream), count, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSampleStatics2> : produce_base<D, Windows::Media::Core::IMediaStreamSampleStatics2>
{
    int32_t WINRT_CALL CreateFromDirect3D11Surface(void* surface, Windows::Foundation::TimeSpan timestamp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDirect3D11Surface, WINRT_WRAP(Windows::Media::Core::MediaStreamSample), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::Media::Core::MediaStreamSample>(this->shim().CreateFromDirect3D11Surface(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSource> : produce_base<D, Windows::Media::Core::IMediaStreamSource>
{
    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Starting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Starting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceStartingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Starting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Starting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Starting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Starting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Paused(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Paused, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Paused(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Paused(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Paused, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Paused(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SampleRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SampleRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SampleRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SampleRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SampleRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SampleRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SwitchStreamsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwitchStreamsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SwitchStreamsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SwitchStreamsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SwitchStreamsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SwitchStreamsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NotifyError(Windows::Media::Core::MediaStreamSourceErrorStatus errorStatus) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyError, WINRT_WRAP(void), Windows::Media::Core::MediaStreamSourceErrorStatus const&);
            this->shim().NotifyError(*reinterpret_cast<Windows::Media::Core::MediaStreamSourceErrorStatus const*>(&errorStatus));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddStreamDescriptor(void* descriptor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddStreamDescriptor, WINRT_WRAP(void), Windows::Media::Core::IMediaStreamDescriptor const&);
            this->shim().AddStreamDescriptor(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MediaProtectionManager(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaProtectionManager, WINRT_WRAP(void), Windows::Media::Protection::MediaProtectionManager const&);
            this->shim().MediaProtectionManager(*reinterpret_cast<Windows::Media::Protection::MediaProtectionManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaProtectionManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaProtectionManager, WINRT_WRAP(Windows::Media::Protection::MediaProtectionManager));
            *value = detach_from<Windows::Media::Protection::MediaProtectionManager>(this->shim().MediaProtectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_CanSeek(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSeek, WINRT_WRAP(void), bool);
            this->shim().CanSeek(value);
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

    int32_t WINRT_CALL put_BufferTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().BufferTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BufferTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBufferedRange(Windows::Foundation::TimeSpan startOffset, Windows::Foundation::TimeSpan endOffset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBufferedRange, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&, Windows::Foundation::TimeSpan const&);
            this->shim().SetBufferedRange(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&startOffset), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&endOffset));
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
            WINRT_ASSERT_DECLARATION(MusicProperties, WINRT_WRAP(Windows::Storage::FileProperties::MusicProperties));
            *value = detach_from<Windows::Storage::FileProperties::MusicProperties>(this->shim().MusicProperties());
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
            WINRT_ASSERT_DECLARATION(VideoProperties, WINRT_WRAP(Windows::Storage::FileProperties::VideoProperties));
            *value = detach_from<Windows::Storage::FileProperties::VideoProperties>(this->shim().VideoProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
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

    int32_t WINRT_CALL AddProtectionKey(void* streamDescriptor, uint32_t __keyIdentifierSize, uint8_t* keyIdentifier, uint32_t __licenseDataSize, uint8_t* licenseData) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddProtectionKey, WINRT_WRAP(void), Windows::Media::Core::IMediaStreamDescriptor const&, array_view<uint8_t const>, array_view<uint8_t const>);
            this->shim().AddProtectionKey(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&streamDescriptor), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(keyIdentifier), reinterpret_cast<uint8_t const *>(keyIdentifier) + __keyIdentifierSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(licenseData), reinterpret_cast<uint8_t const *>(licenseData) + __licenseDataSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSource2> : produce_base<D, Windows::Media::Core::IMediaStreamSource2>
{
    int32_t WINRT_CALL add_SampleRendered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SampleRendered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SampleRendered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MediaStreamSource, Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SampleRendered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SampleRendered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SampleRendered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSource3> : produce_base<D, Windows::Media::Core::IMediaStreamSource3>
{
    int32_t WINRT_CALL put_MaxSupportedPlaybackRate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSupportedPlaybackRate, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().MaxSupportedPlaybackRate(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxSupportedPlaybackRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSupportedPlaybackRate, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().MaxSupportedPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSource4> : produce_base<D, Windows::Media::Core::IMediaStreamSource4>
{
    int32_t WINRT_CALL put_IsLive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLive, WINRT_WRAP(void), bool);
            this->shim().IsLive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceClosedEventArgs> : produce_base<D, Windows::Media::Core::IMediaStreamSourceClosedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceClosedRequest));
            *value = detach_from<Windows::Media::Core::MediaStreamSourceClosedRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceClosedRequest> : produce_base<D, Windows::Media::Core::IMediaStreamSourceClosedRequest>
{
    int32_t WINRT_CALL get_Reason(Windows::Media::Core::MediaStreamSourceClosedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceClosedReason));
            *value = detach_from<Windows::Media::Core::MediaStreamSourceClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceFactory> : produce_base<D, Windows::Media::Core::IMediaStreamSourceFactory>
{
    int32_t WINRT_CALL CreateFromDescriptor(void* descriptor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDescriptor, WINRT_WRAP(Windows::Media::Core::MediaStreamSource), Windows::Media::Core::IMediaStreamDescriptor const&);
            *result = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().CreateFromDescriptor(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromDescriptors(void* descriptor, void* descriptor2, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromDescriptors, WINRT_WRAP(Windows::Media::Core::MediaStreamSource), Windows::Media::Core::IMediaStreamDescriptor const&, Windows::Media::Core::IMediaStreamDescriptor const&);
            *result = detach_from<Windows::Media::Core::MediaStreamSource>(this->shim().CreateFromDescriptors(*reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs>
{
    int32_t WINRT_CALL get_SampleLag(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SampleLag, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SampleLag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceSampleRequest> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSampleRequest>
{
    int32_t WINRT_CALL get_StreamDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamDescriptor, WINRT_WRAP(Windows::Media::Core::IMediaStreamDescriptor));
            *value = detach_from<Windows::Media::Core::IMediaStreamDescriptor>(this->shim().StreamDescriptor());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceSampleRequestDeferral));
            *deferral = detach_from<Windows::Media::Core::MediaStreamSourceSampleRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Sample(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sample, WINRT_WRAP(void), Windows::Media::Core::MediaStreamSample const&);
            this->shim().Sample(*reinterpret_cast<Windows::Media::Core::MediaStreamSample const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sample(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sample, WINRT_WRAP(Windows::Media::Core::MediaStreamSample));
            *value = detach_from<Windows::Media::Core::MediaStreamSample>(this->shim().Sample());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportSampleProgress(uint32_t progress) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportSampleProgress, WINRT_WRAP(void), uint32_t);
            this->shim().ReportSampleProgress(progress);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral>
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
struct produce<D, Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceSampleRequest));
            *value = detach_from<Windows::Media::Core::MediaStreamSourceSampleRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceStartingEventArgs> : produce_base<D, Windows::Media::Core::IMediaStreamSourceStartingEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceStartingRequest));
            *value = detach_from<Windows::Media::Core::MediaStreamSourceStartingRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceStartingRequest> : produce_base<D, Windows::Media::Core::IMediaStreamSourceStartingRequest>
{
    int32_t WINRT_CALL get_StartPosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPosition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().StartPosition());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceStartingRequestDeferral));
            *deferral = detach_from<Windows::Media::Core::MediaStreamSourceStartingRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetActualStartPosition(Windows::Foundation::TimeSpan position) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActualStartPosition, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SetActualStartPosition(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral> : produce_base<D, Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral>
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
struct produce<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest>
{
    int32_t WINRT_CALL get_OldStreamDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldStreamDescriptor, WINRT_WRAP(Windows::Media::Core::IMediaStreamDescriptor));
            *value = detach_from<Windows::Media::Core::IMediaStreamDescriptor>(this->shim().OldStreamDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewStreamDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewStreamDescriptor, WINRT_WRAP(Windows::Media::Core::IMediaStreamDescriptor));
            *value = detach_from<Windows::Media::Core::IMediaStreamDescriptor>(this->shim().NewStreamDescriptor());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral));
            *deferral = detach_from<Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral>
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
struct produce<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs> : produce_base<D, Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest));
            *value = detach_from<Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMediaTrack> : produce_base<D, Windows::Media::Core::IMediaTrack>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackKind(Windows::Media::Core::MediaTrackKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackKind, WINRT_WRAP(Windows::Media::Core::MediaTrackKind));
            *value = detach_from<Windows::Media::Core::MediaTrackKind>(this->shim().TrackKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMseSourceBuffer> : produce_base<D, Windows::Media::Core::IMseSourceBuffer>
{
    int32_t WINRT_CALL add_UpdateStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UpdateStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UpdateStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UpdateStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UpdateStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UpdateEnded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UpdateEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UpdateEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UpdateEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UpdateEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ErrorOccurred(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ErrorOccurred, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Aborted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aborted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Aborted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBuffer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Aborted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Aborted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Aborted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Core::MseAppendMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Core::MseAppendMode));
            *value = detach_from<Windows::Media::Core::MseAppendMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Core::MseAppendMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Core::MseAppendMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Core::MseAppendMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUpdating(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUpdating, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUpdating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Buffered(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffered, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseTimeRange>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseTimeRange>>(this->shim().Buffered());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimestampOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimestampOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TimestampOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TimestampOffset(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimestampOffset, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().TimestampOffset(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppendWindowStart(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendWindowStart, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AppendWindowStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppendWindowStart(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendWindowStart, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().AppendWindowStart(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppendWindowEnd(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendWindowEnd, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().AppendWindowEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppendWindowEnd(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendWindowEnd, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().AppendWindowEnd(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().AppendBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendStream(void* stream) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendStream, WINRT_WRAP(void), Windows::Storage::Streams::IInputStream const&);
            this->shim().AppendStream(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendStreamMaxSize(void* stream, uint64_t maxSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendStream, WINRT_WRAP(void), Windows::Storage::Streams::IInputStream const&, uint64_t);
            this->shim().AppendStream(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream), maxSize);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Abort() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Abort, WINRT_WRAP(void));
            this->shim().Abort();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(Windows::Foundation::TimeSpan start, void* end) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&, Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Remove(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&start), *reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&end));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMseSourceBufferList> : produce_base<D, Windows::Media::Core::IMseSourceBufferList>
{
    int32_t WINRT_CALL add_SourceBufferAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceBufferAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceBufferAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceBufferAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceBufferAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceBufferAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceBufferRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceBufferRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceBufferRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseSourceBufferList, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceBufferRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceBufferRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceBufferRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Buffers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Buffers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseSourceBuffer>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::MseSourceBuffer>>(this->shim().Buffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMseStreamSource> : produce_base<D, Windows::Media::Core::IMseStreamSource>
{
    int32_t WINRT_CALL add_Opened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Opened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Ended(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ended, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Ended(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Ended(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Ended, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Ended(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::MseStreamSource, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_SourceBuffers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceBuffers, WINRT_WRAP(Windows::Media::Core::MseSourceBufferList));
            *value = detach_from<Windows::Media::Core::MseSourceBufferList>(this->shim().SourceBuffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActiveSourceBuffers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActiveSourceBuffers, WINRT_WRAP(Windows::Media::Core::MseSourceBufferList));
            *value = detach_from<Windows::Media::Core::MseSourceBufferList>(this->shim().ActiveSourceBuffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadyState(Windows::Media::Core::MseReadyState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadyState, WINRT_WRAP(Windows::Media::Core::MseReadyState));
            *value = detach_from<Windows::Media::Core::MseReadyState>(this->shim().ReadyState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddSourceBuffer(void* mimeType, void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddSourceBuffer, WINRT_WRAP(Windows::Media::Core::MseSourceBuffer), hstring const&);
            *buffer = detach_from<Windows::Media::Core::MseSourceBuffer>(this->shim().AddSourceBuffer(*reinterpret_cast<hstring const*>(&mimeType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveSourceBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveSourceBuffer, WINRT_WRAP(void), Windows::Media::Core::MseSourceBuffer const&);
            this->shim().RemoveSourceBuffer(*reinterpret_cast<Windows::Media::Core::MseSourceBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndOfStream(Windows::Media::Core::MseEndOfStreamStatus status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndOfStream, WINRT_WRAP(void), Windows::Media::Core::MseEndOfStreamStatus const&);
            this->shim().EndOfStream(*reinterpret_cast<Windows::Media::Core::MseEndOfStreamStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMseStreamSource2> : produce_base<D, Windows::Media::Core::IMseStreamSource2>
{
    int32_t WINRT_CALL get_LiveSeekableRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LiveSeekableRange, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange>>(this->shim().LiveSeekableRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LiveSeekableRange(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LiveSeekableRange, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange> const&);
            this->shim().LiveSeekableRange(*reinterpret_cast<Windows::Foundation::IReference<Windows::Media::Core::MseTimeRange> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IMseStreamSourceStatics> : produce_base<D, Windows::Media::Core::IMseStreamSourceStatics>
{
    int32_t WINRT_CALL IsContentTypeSupported(void* contentType, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentTypeSupported, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsContentTypeSupported(*reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISceneAnalysisEffect> : produce_base<D, Windows::Media::Core::ISceneAnalysisEffect>
{
    int32_t WINRT_CALL get_HighDynamicRangeAnalyzer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighDynamicRangeAnalyzer, WINRT_WRAP(Windows::Media::Core::HighDynamicRangeControl));
            *value = detach_from<Windows::Media::Core::HighDynamicRangeControl>(this->shim().HighDynamicRangeAnalyzer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredAnalysisInterval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAnalysisInterval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DesiredAnalysisInterval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredAnalysisInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAnalysisInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DesiredAnalysisInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SceneAnalyzed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SceneAnalyzed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::SceneAnalysisEffect, Windows::Media::Core::SceneAnalyzedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().SceneAnalyzed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::SceneAnalysisEffect, Windows::Media::Core::SceneAnalyzedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SceneAnalyzed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SceneAnalyzed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SceneAnalyzed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISceneAnalysisEffectFrame> : produce_base<D, Windows::Media::Core::ISceneAnalysisEffectFrame>
{
    int32_t WINRT_CALL get_FrameControlValues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameControlValues, WINRT_WRAP(Windows::Media::Capture::CapturedFrameControlValues));
            *value = detach_from<Windows::Media::Capture::CapturedFrameControlValues>(this->shim().FrameControlValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HighDynamicRange(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighDynamicRange, WINRT_WRAP(Windows::Media::Core::HighDynamicRangeOutput));
            *value = detach_from<Windows::Media::Core::HighDynamicRangeOutput>(this->shim().HighDynamicRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISceneAnalysisEffectFrame2> : produce_base<D, Windows::Media::Core::ISceneAnalysisEffectFrame2>
{
    int32_t WINRT_CALL get_AnalysisRecommendation(Windows::Media::Core::SceneAnalysisRecommendation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnalysisRecommendation, WINRT_WRAP(Windows::Media::Core::SceneAnalysisRecommendation));
            *value = detach_from<Windows::Media::Core::SceneAnalysisRecommendation>(this->shim().AnalysisRecommendation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISceneAnalyzedEventArgs> : produce_base<D, Windows::Media::Core::ISceneAnalyzedEventArgs>
{
    int32_t WINRT_CALL get_ResultFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultFrame, WINRT_WRAP(Windows::Media::Core::SceneAnalysisEffectFrame));
            *value = detach_from<Windows::Media::Core::SceneAnalysisEffectFrame>(this->shim().ResultFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISingleSelectMediaTrackList> : produce_base<D, Windows::Media::Core::ISingleSelectMediaTrackList>
{
    int32_t WINRT_CALL add_SelectedIndexChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndexChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::ISingleSelectMediaTrackList, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SelectedIndexChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::ISingleSelectMediaTrackList, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SelectedIndexChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SelectedIndexChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SelectedIndexChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL put_SelectedIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(void), int32_t);
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ISpeechCue> : produce_base<D, Windows::Media::Core::ISpeechCue>
{
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

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartPositionInInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPositionInInput, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().StartPositionInInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPositionInInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPositionInInput, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().StartPositionInInput(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPositionInInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPositionInInput, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().EndPositionInInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndPositionInInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPositionInInput, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().EndPositionInInput(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataStreamDescriptor> : produce_base<D, Windows::Media::Core::ITimedMetadataStreamDescriptor>
{
    int32_t WINRT_CALL get_EncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::TimedMetadataEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().EncodingProperties());
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
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::Core::TimedMetadataStreamDescriptor));
            *result = detach_from<Windows::Media::Core::TimedMetadataStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataStreamDescriptorFactory> : produce_base<D, Windows::Media::Core::ITimedMetadataStreamDescriptorFactory>
{
    int32_t WINRT_CALL Create(void* encodingProperties, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Core::TimedMetadataStreamDescriptor), Windows::Media::MediaProperties::TimedMetadataEncodingProperties const&);
            *result = detach_from<Windows::Media::Core::TimedMetadataStreamDescriptor>(this->shim().Create(*reinterpret_cast<Windows::Media::MediaProperties::TimedMetadataEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataTrack> : produce_base<D, Windows::Media::Core::ITimedMetadataTrack>
{
    int32_t WINRT_CALL add_CueEntered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CueEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CueEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CueEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CueEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CueExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CueExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::MediaCueEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CueExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CueExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CueExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TrackFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TrackFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedMetadataTrack, Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TrackFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TrackFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TrackFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Cues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cues, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue>>(this->shim().Cues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActiveCues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActiveCues, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::IMediaCue>>(this->shim().ActiveCues());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimedMetadataKind(Windows::Media::Core::TimedMetadataKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimedMetadataKind, WINRT_WRAP(Windows::Media::Core::TimedMetadataKind));
            *value = detach_from<Windows::Media::Core::TimedMetadataKind>(this->shim().TimedMetadataKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DispatchType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispatchType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DispatchType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddCue(void* cue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddCue, WINRT_WRAP(void), Windows::Media::Core::IMediaCue const&);
            this->shim().AddCue(*reinterpret_cast<Windows::Media::Core::IMediaCue const*>(&cue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveCue(void* cue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveCue, WINRT_WRAP(void), Windows::Media::Core::IMediaCue const&);
            this->shim().RemoveCue(*reinterpret_cast<Windows::Media::Core::IMediaCue const*>(&cue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataTrack2> : produce_base<D, Windows::Media::Core::ITimedMetadataTrack2>
{
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

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataTrackError> : produce_base<D, Windows::Media::Core::ITimedMetadataTrackError>
{
    int32_t WINRT_CALL get_ErrorCode(Windows::Media::Core::TimedMetadataTrackErrorCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(Windows::Media::Core::TimedMetadataTrackErrorCode));
            *value = detach_from<Windows::Media::Core::TimedMetadataTrackErrorCode>(this->shim().ErrorCode());
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
struct produce<D, Windows::Media::Core::ITimedMetadataTrackFactory> : produce_base<D, Windows::Media::Core::ITimedMetadataTrackFactory>
{
    int32_t WINRT_CALL Create(void* id, void* language, Windows::Media::Core::TimedMetadataKind kind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Core::TimedMetadataTrack), hstring const&, hstring const&, Windows::Media::Core::TimedMetadataKind const&);
            *value = detach_from<Windows::Media::Core::TimedMetadataTrack>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&language), *reinterpret_cast<Windows::Media::Core::TimedMetadataKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataTrackFailedEventArgs> : produce_base<D, Windows::Media::Core::ITimedMetadataTrackFailedEventArgs>
{
    int32_t WINRT_CALL get_Error(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Media::Core::TimedMetadataTrackError));
            *value = detach_from<Windows::Media::Core::TimedMetadataTrackError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedMetadataTrackProvider> : produce_base<D, Windows::Media::Core::ITimedMetadataTrackProvider>
{
    int32_t WINRT_CALL get_TimedMetadataTracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimedMetadataTracks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack>>(this->shim().TimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextCue> : produce_base<D, Windows::Media::Core::ITimedTextCue>
{
    int32_t WINRT_CALL get_CueRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueRegion, WINRT_WRAP(Windows::Media::Core::TimedTextRegion));
            *value = detach_from<Windows::Media::Core::TimedTextRegion>(this->shim().CueRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CueRegion(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueRegion, WINRT_WRAP(void), Windows::Media::Core::TimedTextRegion const&);
            this->shim().CueRegion(*reinterpret_cast<Windows::Media::Core::TimedTextRegion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CueStyle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueStyle, WINRT_WRAP(Windows::Media::Core::TimedTextStyle));
            *value = detach_from<Windows::Media::Core::TimedTextStyle>(this->shim().CueStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CueStyle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CueStyle, WINRT_WRAP(void), Windows::Media::Core::TimedTextStyle const&);
            this->shim().CueStyle(*reinterpret_cast<Windows::Media::Core::TimedTextStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Lines(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lines, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextLine>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextLine>>(this->shim().Lines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextLine> : produce_base<D, Windows::Media::Core::ITimedTextLine>
{
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

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subformats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subformats, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextSubformat>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedTextSubformat>>(this->shim().Subformats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextRegion> : produce_base<D, Windows::Media::Core::ITimedTextRegion>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(struct struct_Windows_Media_Core_TimedTextPoint* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Media::Core::TimedTextPoint));
            *value = detach_from<Windows::Media::Core::TimedTextPoint>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(struct struct_Windows_Media_Core_TimedTextPoint value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), Windows::Media::Core::TimedTextPoint const&);
            this->shim().Position(*reinterpret_cast<Windows::Media::Core::TimedTextPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extent(struct struct_Windows_Media_Core_TimedTextSize* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extent, WINRT_WRAP(Windows::Media::Core::TimedTextSize));
            *value = detach_from<Windows::Media::Core::TimedTextSize>(this->shim().Extent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Extent(struct struct_Windows_Media_Core_TimedTextSize value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extent, WINRT_WRAP(void), Windows::Media::Core::TimedTextSize const&);
            this->shim().Extent(*reinterpret_cast<Windows::Media::Core::TimedTextSize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Background(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Background(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Background(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WritingMode(Windows::Media::Core::TimedTextWritingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WritingMode, WINRT_WRAP(Windows::Media::Core::TimedTextWritingMode));
            *value = detach_from<Windows::Media::Core::TimedTextWritingMode>(this->shim().WritingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WritingMode(Windows::Media::Core::TimedTextWritingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WritingMode, WINRT_WRAP(void), Windows::Media::Core::TimedTextWritingMode const&);
            this->shim().WritingMode(*reinterpret_cast<Windows::Media::Core::TimedTextWritingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayAlignment(Windows::Media::Core::TimedTextDisplayAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAlignment, WINRT_WRAP(Windows::Media::Core::TimedTextDisplayAlignment));
            *value = detach_from<Windows::Media::Core::TimedTextDisplayAlignment>(this->shim().DisplayAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayAlignment(Windows::Media::Core::TimedTextDisplayAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAlignment, WINRT_WRAP(void), Windows::Media::Core::TimedTextDisplayAlignment const&);
            this->shim().DisplayAlignment(*reinterpret_cast<Windows::Media::Core::TimedTextDisplayAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineHeight(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(Windows::Media::Core::TimedTextDouble));
            *value = detach_from<Windows::Media::Core::TimedTextDouble>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineHeight(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineHeight, WINRT_WRAP(void), Windows::Media::Core::TimedTextDouble const&);
            this->shim().LineHeight(*reinterpret_cast<Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverflowClipped(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverflowClipped, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverflowClipped());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOverflowClipped(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverflowClipped, WINRT_WRAP(void), bool);
            this->shim().IsOverflowClipped(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Padding(struct struct_Windows_Media_Core_TimedTextPadding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Padding, WINRT_WRAP(Windows::Media::Core::TimedTextPadding));
            *value = detach_from<Windows::Media::Core::TimedTextPadding>(this->shim().Padding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Padding(struct struct_Windows_Media_Core_TimedTextPadding value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Padding, WINRT_WRAP(void), Windows::Media::Core::TimedTextPadding const&);
            this->shim().Padding(*reinterpret_cast<Windows::Media::Core::TimedTextPadding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextWrapping(Windows::Media::Core::TimedTextWrapping* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextWrapping, WINRT_WRAP(Windows::Media::Core::TimedTextWrapping));
            *value = detach_from<Windows::Media::Core::TimedTextWrapping>(this->shim().TextWrapping());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextWrapping(Windows::Media::Core::TimedTextWrapping value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextWrapping, WINRT_WRAP(void), Windows::Media::Core::TimedTextWrapping const&);
            this->shim().TextWrapping(*reinterpret_cast<Windows::Media::Core::TimedTextWrapping const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(void), int32_t);
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollMode(Windows::Media::Core::TimedTextScrollMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollMode, WINRT_WRAP(Windows::Media::Core::TimedTextScrollMode));
            *value = detach_from<Windows::Media::Core::TimedTextScrollMode>(this->shim().ScrollMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScrollMode(Windows::Media::Core::TimedTextScrollMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollMode, WINRT_WRAP(void), Windows::Media::Core::TimedTextScrollMode const&);
            this->shim().ScrollMode(*reinterpret_cast<Windows::Media::Core::TimedTextScrollMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextSource> : produce_base<D, Windows::Media::Core::ITimedTextSource>
{
    int32_t WINRT_CALL add_Resolved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resolved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedTextSource, Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Resolved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::TimedTextSource, Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Resolved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Resolved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Resolved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextSourceResolveResultEventArgs> : produce_base<D, Windows::Media::Core::ITimedTextSourceResolveResultEventArgs>
{
    int32_t WINRT_CALL get_Error(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Media::Core::TimedMetadataTrackError));
            *value = detach_from<Windows::Media::Core::TimedMetadataTrackError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tracks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tracks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Core::TimedMetadataTrack>>(this->shim().Tracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextSourceStatics> : produce_base<D, Windows::Media::Core::ITimedTextSourceStatics>
{
    int32_t WINRT_CALL CreateFromStream(void* stream, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStream, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Storage::Streams::IRandomAccessStream const&);
            *value = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUri(void* uri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUri, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Foundation::Uri const&);
            *value = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamWithLanguage(void* stream, void* defaultLanguage, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStream, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Storage::Streams::IRandomAccessStream const&, hstring const&);
            *value = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUriWithLanguage(void* uri, void* defaultLanguage, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUri, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Foundation::Uri const&, hstring const&);
            *value = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextSourceStatics2> : produce_base<D, Windows::Media::Core::ITimedTextSourceStatics2>
{
    int32_t WINRT_CALL CreateFromStreamWithIndex(void* stream, void* indexStream, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamWithIndex, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Storage::Streams::IRandomAccessStream const&, Windows::Storage::Streams::IRandomAccessStream const&);
            *result = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStreamWithIndex(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&indexStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUriWithIndex(void* uri, void* indexUri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUriWithIndex, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Foundation::Uri const&, Windows::Foundation::Uri const&);
            *result = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUriWithIndex(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Uri const*>(&indexUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStreamWithIndexAndLanguage(void* stream, void* indexStream, void* defaultLanguage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStreamWithIndex, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Storage::Streams::IRandomAccessStream const&, Windows::Storage::Streams::IRandomAccessStream const&, hstring const&);
            *result = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStreamWithIndex(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&indexStream), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromUriWithIndexAndLanguage(void* uri, void* indexUri, void* defaultLanguage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromUriWithIndex, WINRT_WRAP(Windows::Media::Core::TimedTextSource), Windows::Foundation::Uri const&, Windows::Foundation::Uri const&, hstring const&);
            *result = detach_from<Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUriWithIndex(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Uri const*>(&indexUri), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextStyle> : produce_base<D, Windows::Media::Core::ITimedTextStyle>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontFamily(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamily, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontFamily(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamily, WINRT_WRAP(void), hstring const&);
            this->shim().FontFamily(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontSize(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSize, WINRT_WRAP(Windows::Media::Core::TimedTextDouble));
            *value = detach_from<Windows::Media::Core::TimedTextDouble>(this->shim().FontSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontSize(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSize, WINRT_WRAP(void), Windows::Media::Core::TimedTextDouble const&);
            this->shim().FontSize(*reinterpret_cast<Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontWeight(Windows::Media::Core::TimedTextWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeight, WINRT_WRAP(Windows::Media::Core::TimedTextWeight));
            *value = detach_from<Windows::Media::Core::TimedTextWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontWeight(Windows::Media::Core::TimedTextWeight value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeight, WINRT_WRAP(void), Windows::Media::Core::TimedTextWeight const&);
            this->shim().FontWeight(*reinterpret_cast<Windows::Media::Core::TimedTextWeight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Foreground(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Foreground(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Foreground, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Foreground(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Background(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Background(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Background, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Background(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBackgroundAlwaysShown(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBackgroundAlwaysShown, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBackgroundAlwaysShown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsBackgroundAlwaysShown(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBackgroundAlwaysShown, WINRT_WRAP(void), bool);
            this->shim().IsBackgroundAlwaysShown(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowDirection(Windows::Media::Core::TimedTextFlowDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(Windows::Media::Core::TimedTextFlowDirection));
            *value = detach_from<Windows::Media::Core::TimedTextFlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FlowDirection(Windows::Media::Core::TimedTextFlowDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(void), Windows::Media::Core::TimedTextFlowDirection const&);
            this->shim().FlowDirection(*reinterpret_cast<Windows::Media::Core::TimedTextFlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineAlignment(Windows::Media::Core::TimedTextLineAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineAlignment, WINRT_WRAP(Windows::Media::Core::TimedTextLineAlignment));
            *value = detach_from<Windows::Media::Core::TimedTextLineAlignment>(this->shim().LineAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LineAlignment(Windows::Media::Core::TimedTextLineAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineAlignment, WINRT_WRAP(void), Windows::Media::Core::TimedTextLineAlignment const&);
            this->shim().LineAlignment(*reinterpret_cast<Windows::Media::Core::TimedTextLineAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutlineColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OutlineColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutlineColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().OutlineColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutlineThickness(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineThickness, WINRT_WRAP(Windows::Media::Core::TimedTextDouble));
            *value = detach_from<Windows::Media::Core::TimedTextDouble>(this->shim().OutlineThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutlineThickness(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineThickness, WINRT_WRAP(void), Windows::Media::Core::TimedTextDouble const&);
            this->shim().OutlineThickness(*reinterpret_cast<Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutlineRadius(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineRadius, WINRT_WRAP(Windows::Media::Core::TimedTextDouble));
            *value = detach_from<Windows::Media::Core::TimedTextDouble>(this->shim().OutlineRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutlineRadius(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineRadius, WINRT_WRAP(void), Windows::Media::Core::TimedTextDouble const&);
            this->shim().OutlineRadius(*reinterpret_cast<Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextStyle2> : produce_base<D, Windows::Media::Core::ITimedTextStyle2>
{
    int32_t WINRT_CALL get_FontStyle(Windows::Media::Core::TimedTextFontStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(Windows::Media::Core::TimedTextFontStyle));
            *value = detach_from<Windows::Media::Core::TimedTextFontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontStyle(Windows::Media::Core::TimedTextFontStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(void), Windows::Media::Core::TimedTextFontStyle const&);
            this->shim().FontStyle(*reinterpret_cast<Windows::Media::Core::TimedTextFontStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUnderlineEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUnderlineEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUnderlineEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsUnderlineEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUnderlineEnabled, WINRT_WRAP(void), bool);
            this->shim().IsUnderlineEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLineThroughEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLineThroughEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLineThroughEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsLineThroughEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLineThroughEnabled, WINRT_WRAP(void), bool);
            this->shim().IsLineThroughEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverlineEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverlineEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverlineEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOverlineEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverlineEnabled, WINRT_WRAP(void), bool);
            this->shim().IsOverlineEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::ITimedTextSubformat> : produce_base<D, Windows::Media::Core::ITimedTextSubformat>
{
    int32_t WINRT_CALL get_StartIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StartIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartIndex, WINRT_WRAP(void), int32_t);
            this->shim().StartIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Length(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(void), int32_t);
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubformatStyle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubformatStyle, WINRT_WRAP(Windows::Media::Core::TimedTextStyle));
            *value = detach_from<Windows::Media::Core::TimedTextStyle>(this->shim().SubformatStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SubformatStyle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubformatStyle, WINRT_WRAP(void), Windows::Media::Core::TimedTextStyle const&);
            this->shim().SubformatStyle(*reinterpret_cast<Windows::Media::Core::TimedTextStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoStabilizationEffect> : produce_base<D, Windows::Media::Core::IVideoStabilizationEffect>
{
    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_EnabledChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoStabilizationEffect, Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().EnabledChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoStabilizationEffect, Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnabledChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnabledChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL GetRecommendedStreamConfiguration(void* controller, void* desiredProperties, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecommendedStreamConfiguration, WINRT_WRAP(Windows::Media::Capture::VideoStreamConfiguration), Windows::Media::Devices::VideoDeviceController const&, Windows::Media::MediaProperties::VideoEncodingProperties const&);
            *value = detach_from<Windows::Media::Capture::VideoStreamConfiguration>(this->shim().GetRecommendedStreamConfiguration(*reinterpret_cast<Windows::Media::Devices::VideoDeviceController const*>(&controller), *reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingProperties const*>(&desiredProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs> : produce_base<D, Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason));
            *value = detach_from<Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoStreamDescriptor> : produce_base<D, Windows::Media::Core::IVideoStreamDescriptor>
{
    int32_t WINRT_CALL get_EncodingProperties(void** encodingProperties) noexcept final
    {
        try
        {
            *encodingProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *encodingProperties = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoStreamDescriptor2> : produce_base<D, Windows::Media::Core::IVideoStreamDescriptor2>
{
    int32_t WINRT_CALL Copy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Media::Core::VideoStreamDescriptor));
            *result = detach_from<Windows::Media::Core::VideoStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoStreamDescriptorFactory> : produce_base<D, Windows::Media::Core::IVideoStreamDescriptorFactory>
{
    int32_t WINRT_CALL Create(void* encodingProperties, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Core::VideoStreamDescriptor), Windows::Media::MediaProperties::VideoEncodingProperties const&);
            *result = detach_from<Windows::Media::Core::VideoStreamDescriptor>(this->shim().Create(*reinterpret_cast<Windows::Media::MediaProperties::VideoEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoTrack> : produce_base<D, Windows::Media::Core::IVideoTrack>
{
    int32_t WINRT_CALL add_OpenFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoTrack, Windows::Media::Core::VideoTrackOpenFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Core::VideoTrack, Windows::Media::Core::VideoTrackOpenFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OpenFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().GetEncodingProperties());
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

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportInfo, WINRT_WRAP(Windows::Media::Core::VideoTrackSupportInfo));
            *value = detach_from<Windows::Media::Core::VideoTrackSupportInfo>(this->shim().SupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Core::IVideoTrackOpenFailedEventArgs> : produce_base<D, Windows::Media::Core::IVideoTrackOpenFailedEventArgs>
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
struct produce<D, Windows::Media::Core::IVideoTrackSupportInfo> : produce_base<D, Windows::Media::Core::IVideoTrackSupportInfo>
{
    int32_t WINRT_CALL get_DecoderStatus(Windows::Media::Core::MediaDecoderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecoderStatus, WINRT_WRAP(Windows::Media::Core::MediaDecoderStatus));
            *value = detach_from<Windows::Media::Core::MediaDecoderStatus>(this->shim().DecoderStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaSourceStatus(Windows::Media::Core::MediaSourceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaSourceStatus, WINRT_WRAP(Windows::Media::Core::MediaSourceStatus));
            *value = detach_from<Windows::Media::Core::MediaSourceStatus>(this->shim().MediaSourceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Core {

inline AudioStreamDescriptor::AudioStreamDescriptor(Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) :
    AudioStreamDescriptor(impl::call_factory<AudioStreamDescriptor, Windows::Media::Core::IAudioStreamDescriptorFactory>([&](auto&& f) { return f.Create(encodingProperties); }))
{}

inline ChapterCue::ChapterCue() :
    ChapterCue(impl::call_factory<ChapterCue>([](auto&& f) { return f.template ActivateInstance<ChapterCue>(); }))
{}

inline CodecQuery::CodecQuery() :
    CodecQuery(impl::call_factory<CodecQuery>([](auto&& f) { return f.template ActivateInstance<CodecQuery>(); }))
{}

inline hstring CodecSubtypes::VideoFormatDV25()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDV25(); });
}

inline hstring CodecSubtypes::VideoFormatDV50()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDV50(); });
}

inline hstring CodecSubtypes::VideoFormatDvc()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDvc(); });
}

inline hstring CodecSubtypes::VideoFormatDvh1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDvh1(); });
}

inline hstring CodecSubtypes::VideoFormatDvhD()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDvhD(); });
}

inline hstring CodecSubtypes::VideoFormatDvsd()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDvsd(); });
}

inline hstring CodecSubtypes::VideoFormatDvsl()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatDvsl(); });
}

inline hstring CodecSubtypes::VideoFormatH263()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatH263(); });
}

inline hstring CodecSubtypes::VideoFormatH264()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatH264(); });
}

inline hstring CodecSubtypes::VideoFormatH265()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatH265(); });
}

inline hstring CodecSubtypes::VideoFormatH264ES()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatH264ES(); });
}

inline hstring CodecSubtypes::VideoFormatHevc()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatHevc(); });
}

inline hstring CodecSubtypes::VideoFormatHevcES()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatHevcES(); });
}

inline hstring CodecSubtypes::VideoFormatM4S2()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatM4S2(); });
}

inline hstring CodecSubtypes::VideoFormatMjpg()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMjpg(); });
}

inline hstring CodecSubtypes::VideoFormatMP43()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMP43(); });
}

inline hstring CodecSubtypes::VideoFormatMP4S()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMP4S(); });
}

inline hstring CodecSubtypes::VideoFormatMP4V()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMP4V(); });
}

inline hstring CodecSubtypes::VideoFormatMpeg2()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMpeg2(); });
}

inline hstring CodecSubtypes::VideoFormatVP80()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatVP80(); });
}

inline hstring CodecSubtypes::VideoFormatVP90()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatVP90(); });
}

inline hstring CodecSubtypes::VideoFormatMpg1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMpg1(); });
}

inline hstring CodecSubtypes::VideoFormatMss1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMss1(); });
}

inline hstring CodecSubtypes::VideoFormatMss2()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatMss2(); });
}

inline hstring CodecSubtypes::VideoFormatWmv1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatWmv1(); });
}

inline hstring CodecSubtypes::VideoFormatWmv2()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatWmv2(); });
}

inline hstring CodecSubtypes::VideoFormatWmv3()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatWmv3(); });
}

inline hstring CodecSubtypes::VideoFormatWvc1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormatWvc1(); });
}

inline hstring CodecSubtypes::VideoFormat420O()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.VideoFormat420O(); });
}

inline hstring CodecSubtypes::AudioFormatAac()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAac(); });
}

inline hstring CodecSubtypes::AudioFormatAdts()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAdts(); });
}

inline hstring CodecSubtypes::AudioFormatAlac()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAlac(); });
}

inline hstring CodecSubtypes::AudioFormatAmrNB()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAmrNB(); });
}

inline hstring CodecSubtypes::AudioFormatAmrWB()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAmrWB(); });
}

inline hstring CodecSubtypes::AudioFormatAmrWP()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatAmrWP(); });
}

inline hstring CodecSubtypes::AudioFormatDolbyAC3()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatDolbyAC3(); });
}

inline hstring CodecSubtypes::AudioFormatDolbyAC3Spdif()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatDolbyAC3Spdif(); });
}

inline hstring CodecSubtypes::AudioFormatDolbyDDPlus()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatDolbyDDPlus(); });
}

inline hstring CodecSubtypes::AudioFormatDrm()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatDrm(); });
}

inline hstring CodecSubtypes::AudioFormatDts()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatDts(); });
}

inline hstring CodecSubtypes::AudioFormatFlac()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatFlac(); });
}

inline hstring CodecSubtypes::AudioFormatFloat()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatFloat(); });
}

inline hstring CodecSubtypes::AudioFormatMP3()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatMP3(); });
}

inline hstring CodecSubtypes::AudioFormatMPeg()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatMPeg(); });
}

inline hstring CodecSubtypes::AudioFormatMsp1()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatMsp1(); });
}

inline hstring CodecSubtypes::AudioFormatOpus()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatOpus(); });
}

inline hstring CodecSubtypes::AudioFormatPcm()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatPcm(); });
}

inline hstring CodecSubtypes::AudioFormatWmaSpdif()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatWmaSpdif(); });
}

inline hstring CodecSubtypes::AudioFormatWMAudioLossless()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatWMAudioLossless(); });
}

inline hstring CodecSubtypes::AudioFormatWMAudioV8()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatWMAudioV8(); });
}

inline hstring CodecSubtypes::AudioFormatWMAudioV9()
{
    return impl::call_factory<CodecSubtypes, Windows::Media::Core::ICodecSubtypesStatics>([&](auto&& f) { return f.AudioFormatWMAudioV9(); });
}

inline DataCue::DataCue() :
    DataCue(impl::call_factory<DataCue>([](auto&& f) { return f.template ActivateInstance<DataCue>(); }))
{}

inline FaceDetectionEffectDefinition::FaceDetectionEffectDefinition() :
    FaceDetectionEffectDefinition(impl::call_factory<FaceDetectionEffectDefinition>([](auto&& f) { return f.template ActivateInstance<FaceDetectionEffectDefinition>(); }))
{}

inline ImageCue::ImageCue() :
    ImageCue(impl::call_factory<ImageCue>([](auto&& f) { return f.template ActivateInstance<ImageCue>(); }))
{}

inline Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapPixelFormat> LowLightFusion::SupportedBitmapPixelFormats()
{
    return impl::call_factory<LowLightFusion, Windows::Media::Core::ILowLightFusionStatics>([&](auto&& f) { return f.SupportedBitmapPixelFormats(); });
}

inline int32_t LowLightFusion::MaxSupportedFrameCount()
{
    return impl::call_factory<LowLightFusion, Windows::Media::Core::ILowLightFusionStatics>([&](auto&& f) { return f.MaxSupportedFrameCount(); });
}

inline Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Core::LowLightFusionResult, double> LowLightFusion::FuseAsync(param::async_iterable<Windows::Graphics::Imaging::SoftwareBitmap> const& frameSet)
{
    return impl::call_factory<LowLightFusion, Windows::Media::Core::ILowLightFusionStatics>([&](auto&& f) { return f.FuseAsync(frameSet); });
}

inline MediaBinder::MediaBinder() :
    MediaBinder(impl::call_factory<MediaBinder>([](auto&& f) { return f.template ActivateInstance<MediaBinder>(); }))
{}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromAdaptiveMediaSource(Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromAdaptiveMediaSource(mediaSource); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromMediaStreamSource(Windows::Media::Core::MediaStreamSource const& mediaSource)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromMediaStreamSource(mediaSource); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromMseStreamSource(Windows::Media::Core::MseStreamSource const& mediaSource)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromMseStreamSource(mediaSource); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromIMediaSource(Windows::Media::Core::IMediaSource const& mediaSource)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromIMediaSource(mediaSource); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromStorageFile(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromStorageFile(file); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromStream(stream, contentType); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromStreamReference(Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromStreamReference(stream, contentType); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromUri(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics>([&](auto&& f) { return f.CreateFromUri(uri); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromMediaBinder(Windows::Media::Core::MediaBinder const& binder)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics2>([&](auto&& f) { return f.CreateFromMediaBinder(binder); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromMediaFrameSource(Windows::Media::Capture::Frames::MediaFrameSource const& frameSource)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics3>([&](auto&& f) { return f.CreateFromMediaFrameSource(frameSource); });
}

inline Windows::Media::Core::MediaSource MediaSource::CreateFromDownloadOperation(Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation)
{
    return impl::call_factory<MediaSource, Windows::Media::Core::IMediaSourceStatics4>([&](auto&& f) { return f.CreateFromDownloadOperation(downloadOperation); });
}

inline MediaSourceAppServiceConnection::MediaSourceAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) :
    MediaSourceAppServiceConnection(impl::call_factory<MediaSourceAppServiceConnection, Windows::Media::Core::IMediaSourceAppServiceConnectionFactory>([&](auto&& f) { return f.Create(appServiceConnection); }))
{}

inline Windows::Media::Core::MediaStreamSample MediaStreamSample::CreateFromBuffer(Windows::Storage::Streams::IBuffer const& buffer, Windows::Foundation::TimeSpan const& timestamp)
{
    return impl::call_factory<MediaStreamSample, Windows::Media::Core::IMediaStreamSampleStatics>([&](auto&& f) { return f.CreateFromBuffer(buffer, timestamp); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Core::MediaStreamSample> MediaStreamSample::CreateFromStreamAsync(Windows::Storage::Streams::IInputStream const& stream, uint32_t count, Windows::Foundation::TimeSpan const& timestamp)
{
    return impl::call_factory<MediaStreamSample, Windows::Media::Core::IMediaStreamSampleStatics>([&](auto&& f) { return f.CreateFromStreamAsync(stream, count, timestamp); });
}

inline Windows::Media::Core::MediaStreamSample MediaStreamSample::CreateFromDirect3D11Surface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Foundation::TimeSpan const& timestamp)
{
    return impl::call_factory<MediaStreamSample, Windows::Media::Core::IMediaStreamSampleStatics2>([&](auto&& f) { return f.CreateFromDirect3D11Surface(surface, timestamp); });
}

inline MediaStreamSource::MediaStreamSource(Windows::Media::Core::IMediaStreamDescriptor const& descriptor) :
    MediaStreamSource(impl::call_factory<MediaStreamSource, Windows::Media::Core::IMediaStreamSourceFactory>([&](auto&& f) { return f.CreateFromDescriptor(descriptor); }))
{}

inline MediaStreamSource::MediaStreamSource(Windows::Media::Core::IMediaStreamDescriptor const& descriptor, Windows::Media::Core::IMediaStreamDescriptor const& descriptor2) :
    MediaStreamSource(impl::call_factory<MediaStreamSource, Windows::Media::Core::IMediaStreamSourceFactory>([&](auto&& f) { return f.CreateFromDescriptors(descriptor, descriptor2); }))
{}

inline MseStreamSource::MseStreamSource() :
    MseStreamSource(impl::call_factory<MseStreamSource>([](auto&& f) { return f.template ActivateInstance<MseStreamSource>(); }))
{}

inline bool MseStreamSource::IsContentTypeSupported(param::hstring const& contentType)
{
    return impl::call_factory<MseStreamSource, Windows::Media::Core::IMseStreamSourceStatics>([&](auto&& f) { return f.IsContentTypeSupported(contentType); });
}

inline SceneAnalysisEffectDefinition::SceneAnalysisEffectDefinition() :
    SceneAnalysisEffectDefinition(impl::call_factory<SceneAnalysisEffectDefinition>([](auto&& f) { return f.template ActivateInstance<SceneAnalysisEffectDefinition>(); }))
{}

inline SpeechCue::SpeechCue() :
    SpeechCue(impl::call_factory<SpeechCue>([](auto&& f) { return f.template ActivateInstance<SpeechCue>(); }))
{}

inline TimedMetadataStreamDescriptor::TimedMetadataStreamDescriptor(Windows::Media::MediaProperties::TimedMetadataEncodingProperties const& encodingProperties) :
    TimedMetadataStreamDescriptor(impl::call_factory<TimedMetadataStreamDescriptor, Windows::Media::Core::ITimedMetadataStreamDescriptorFactory>([&](auto&& f) { return f.Create(encodingProperties); }))
{}

inline TimedMetadataTrack::TimedMetadataTrack(param::hstring const& id, param::hstring const& language, Windows::Media::Core::TimedMetadataKind const& kind) :
    TimedMetadataTrack(impl::call_factory<TimedMetadataTrack, Windows::Media::Core::ITimedMetadataTrackFactory>([&](auto&& f) { return f.Create(id, language, kind); }))
{}

inline TimedTextCue::TimedTextCue() :
    TimedTextCue(impl::call_factory<TimedTextCue>([](auto&& f) { return f.template ActivateInstance<TimedTextCue>(); }))
{}

inline TimedTextLine::TimedTextLine() :
    TimedTextLine(impl::call_factory<TimedTextLine>([](auto&& f) { return f.template ActivateInstance<TimedTextLine>(); }))
{}

inline TimedTextRegion::TimedTextRegion() :
    TimedTextRegion(impl::call_factory<TimedTextRegion>([](auto&& f) { return f.template ActivateInstance<TimedTextRegion>(); }))
{}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics>([&](auto&& f) { return f.CreateFromStream(stream); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromUri(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics>([&](auto&& f) { return f.CreateFromUri(uri); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromStream(Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& defaultLanguage)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics>([&](auto&& f) { return f.CreateFromStream(stream, defaultLanguage); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromUri(Windows::Foundation::Uri const& uri, param::hstring const& defaultLanguage)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics>([&](auto&& f) { return f.CreateFromUri(uri, defaultLanguage); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromStreamWithIndex(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Storage::Streams::IRandomAccessStream const& indexStream)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics2>([&](auto&& f) { return f.CreateFromStreamWithIndex(stream, indexStream); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromUriWithIndex(Windows::Foundation::Uri const& uri, Windows::Foundation::Uri const& indexUri)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics2>([&](auto&& f) { return f.CreateFromUriWithIndex(uri, indexUri); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromStreamWithIndex(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Storage::Streams::IRandomAccessStream const& indexStream, param::hstring const& defaultLanguage)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics2>([&](auto&& f) { return f.CreateFromStreamWithIndex(stream, indexStream, defaultLanguage); });
}

inline Windows::Media::Core::TimedTextSource TimedTextSource::CreateFromUriWithIndex(Windows::Foundation::Uri const& uri, Windows::Foundation::Uri const& indexUri, param::hstring const& defaultLanguage)
{
    return impl::call_factory<TimedTextSource, Windows::Media::Core::ITimedTextSourceStatics2>([&](auto&& f) { return f.CreateFromUriWithIndex(uri, indexUri, defaultLanguage); });
}

inline TimedTextStyle::TimedTextStyle() :
    TimedTextStyle(impl::call_factory<TimedTextStyle>([](auto&& f) { return f.template ActivateInstance<TimedTextStyle>(); }))
{}

inline TimedTextSubformat::TimedTextSubformat() :
    TimedTextSubformat(impl::call_factory<TimedTextSubformat>([](auto&& f) { return f.template ActivateInstance<TimedTextSubformat>(); }))
{}

inline VideoStabilizationEffectDefinition::VideoStabilizationEffectDefinition() :
    VideoStabilizationEffectDefinition(impl::call_factory<VideoStabilizationEffectDefinition>([](auto&& f) { return f.template ActivateInstance<VideoStabilizationEffectDefinition>(); }))
{}

inline VideoStreamDescriptor::VideoStreamDescriptor(Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties) :
    VideoStreamDescriptor(impl::call_factory<VideoStreamDescriptor, Windows::Media::Core::IVideoStreamDescriptorFactory>([&](auto&& f) { return f.Create(encodingProperties); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioStreamDescriptor2> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor3> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioStreamDescriptor3> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptorFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioStreamDescriptorFactory> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioTrack> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IAudioTrackSupportInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::IAudioTrackSupportInfo> {};
template<> struct hash<winrt::Windows::Media::Core::IChapterCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::IChapterCue> {};
template<> struct hash<winrt::Windows::Media::Core::ICodecInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::ICodecInfo> {};
template<> struct hash<winrt::Windows::Media::Core::ICodecQuery> : winrt::impl::hash_base<winrt::Windows::Media::Core::ICodecQuery> {};
template<> struct hash<winrt::Windows::Media::Core::ICodecSubtypesStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::ICodecSubtypesStatics> {};
template<> struct hash<winrt::Windows::Media::Core::IDataCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::IDataCue> {};
template<> struct hash<winrt::Windows::Media::Core::IDataCue2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IDataCue2> {};
template<> struct hash<winrt::Windows::Media::Core::IFaceDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IFaceDetectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::IFaceDetectionEffect> {};
template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Core::IFaceDetectionEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffectFrame> : winrt::impl::hash_base<winrt::Windows::Media::Core::IFaceDetectionEffectFrame> {};
template<> struct hash<winrt::Windows::Media::Core::IHighDynamicRangeControl> : winrt::impl::hash_base<winrt::Windows::Media::Core::IHighDynamicRangeControl> {};
template<> struct hash<winrt::Windows::Media::Core::IHighDynamicRangeOutput> : winrt::impl::hash_base<winrt::Windows::Media::Core::IHighDynamicRangeOutput> {};
template<> struct hash<winrt::Windows::Media::Core::IImageCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::IImageCue> {};
template<> struct hash<winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::ILowLightFusionResult> : winrt::impl::hash_base<winrt::Windows::Media::Core::ILowLightFusionResult> {};
template<> struct hash<winrt::Windows::Media::Core::ILowLightFusionStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::ILowLightFusionStatics> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaBinder> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaBinder> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaBindingEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaBindingEventArgs2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs3> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaBindingEventArgs3> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaCue> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaCueEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaCueEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSource> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSource2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSource2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSource3> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSource3> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSource4> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSource4> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSource5> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSource5> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceAppServiceConnection> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceAppServiceConnection> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceError> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceError> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceStatics> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceStatics2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics3> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceStatics3> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics4> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaSourceStatics4> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamDescriptor2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamDescriptor2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSample> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSample> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSample2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSample2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSampleStatics> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSampleStatics2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSource> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSource2> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource3> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSource3> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource4> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSource4> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceFactory> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IMediaTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMediaTrack> {};
template<> struct hash<winrt::Windows::Media::Core::IMseSourceBuffer> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMseSourceBuffer> {};
template<> struct hash<winrt::Windows::Media::Core::IMseSourceBufferList> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMseSourceBufferList> {};
template<> struct hash<winrt::Windows::Media::Core::IMseStreamSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMseStreamSource> {};
template<> struct hash<winrt::Windows::Media::Core::IMseStreamSource2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMseStreamSource2> {};
template<> struct hash<winrt::Windows::Media::Core::IMseStreamSourceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::IMseStreamSourceStatics> {};
template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISceneAnalysisEffect> {};
template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame> {};
template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2> {};
template<> struct hash<winrt::Windows::Media::Core::ISceneAnalyzedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISceneAnalyzedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::ISingleSelectMediaTrackList> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISingleSelectMediaTrackList> {};
template<> struct hash<winrt::Windows::Media::Core::ISpeechCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::ISpeechCue> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrack> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrack2> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrack2> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackError> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrackError> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrackFactory> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackProvider> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedMetadataTrackProvider> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextCue> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextLine> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextLine> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextRegion> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextRegion> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextSource> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextSourceStatics> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextSourceStatics2> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextStyle> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextStyle> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextStyle2> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextStyle2> {};
template<> struct hash<winrt::Windows::Media::Core::ITimedTextSubformat> : winrt::impl::hash_base<winrt::Windows::Media::Core::ITimedTextSubformat> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoStabilizationEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoStabilizationEffect> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptor2> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoStreamDescriptor2> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptorFactory> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoStreamDescriptorFactory> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoTrack> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::IVideoTrackSupportInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::IVideoTrackSupportInfo> {};
template<> struct hash<winrt::Windows::Media::Core::AudioStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::AudioStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::AudioTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::AudioTrack> {};
template<> struct hash<winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::AudioTrackSupportInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::AudioTrackSupportInfo> {};
template<> struct hash<winrt::Windows::Media::Core::ChapterCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::ChapterCue> {};
template<> struct hash<winrt::Windows::Media::Core::CodecInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::CodecInfo> {};
template<> struct hash<winrt::Windows::Media::Core::CodecQuery> : winrt::impl::hash_base<winrt::Windows::Media::Core::CodecQuery> {};
template<> struct hash<winrt::Windows::Media::Core::CodecSubtypes> : winrt::impl::hash_base<winrt::Windows::Media::Core::CodecSubtypes> {};
template<> struct hash<winrt::Windows::Media::Core::DataCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::DataCue> {};
template<> struct hash<winrt::Windows::Media::Core::FaceDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::FaceDetectedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::FaceDetectionEffect> {};
template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Core::FaceDetectionEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffectFrame> : winrt::impl::hash_base<winrt::Windows::Media::Core::FaceDetectionEffectFrame> {};
template<> struct hash<winrt::Windows::Media::Core::HighDynamicRangeControl> : winrt::impl::hash_base<winrt::Windows::Media::Core::HighDynamicRangeControl> {};
template<> struct hash<winrt::Windows::Media::Core::HighDynamicRangeOutput> : winrt::impl::hash_base<winrt::Windows::Media::Core::HighDynamicRangeOutput> {};
template<> struct hash<winrt::Windows::Media::Core::ImageCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::ImageCue> {};
template<> struct hash<winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::LowLightFusion> : winrt::impl::hash_base<winrt::Windows::Media::Core::LowLightFusion> {};
template<> struct hash<winrt::Windows::Media::Core::LowLightFusionResult> : winrt::impl::hash_base<winrt::Windows::Media::Core::LowLightFusionResult> {};
template<> struct hash<winrt::Windows::Media::Core::MediaBinder> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaBinder> {};
template<> struct hash<winrt::Windows::Media::Core::MediaBindingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaBindingEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaCueEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaCueEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaSource> {};
template<> struct hash<winrt::Windows::Media::Core::MediaSourceAppServiceConnection> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaSourceAppServiceConnection> {};
template<> struct hash<winrt::Windows::Media::Core::MediaSourceError> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaSourceError> {};
template<> struct hash<winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSample> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSample> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSamplePropertySet> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSamplePropertySet> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSource> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceClosedRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceClosedRequest> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSampleRequest> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceStartingRequest> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral> {};
template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::MseSourceBuffer> : winrt::impl::hash_base<winrt::Windows::Media::Core::MseSourceBuffer> {};
template<> struct hash<winrt::Windows::Media::Core::MseSourceBufferList> : winrt::impl::hash_base<winrt::Windows::Media::Core::MseSourceBufferList> {};
template<> struct hash<winrt::Windows::Media::Core::MseStreamSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::MseStreamSource> {};
template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::SceneAnalysisEffect> {};
template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Core::SceneAnalysisEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffectFrame> : winrt::impl::hash_base<winrt::Windows::Media::Core::SceneAnalysisEffectFrame> {};
template<> struct hash<winrt::Windows::Media::Core::SceneAnalyzedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::SceneAnalyzedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::SpeechCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::SpeechCue> {};
template<> struct hash<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedMetadataTrack> {};
template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrackError> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedMetadataTrackError> {};
template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextCue> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextCue> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextLine> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextLine> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextRegion> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextRegion> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextSource> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextSource> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextStyle> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextStyle> {};
template<> struct hash<winrt::Windows::Media::Core::TimedTextSubformat> : winrt::impl::hash_base<winrt::Windows::Media::Core::TimedTextSubformat> {};
template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffect> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoStabilizationEffect> {};
template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffectDefinition> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoStabilizationEffectDefinition> {};
template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::VideoStreamDescriptor> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoStreamDescriptor> {};
template<> struct hash<winrt::Windows::Media::Core::VideoTrack> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoTrack> {};
template<> struct hash<winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Core::VideoTrackSupportInfo> : winrt::impl::hash_base<winrt::Windows::Media::Core::VideoTrackSupportInfo> {};

}
