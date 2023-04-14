// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
#include "winrt/Windows.Media.Capture.h"

namespace winrt::impl {

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::FrameReference() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IAudioMediaFrame)->get_FrameReference(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::AudioEncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IAudioMediaFrame)->get_AudioEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AudioFrame consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::GetAudioFrame() const
{
    Windows::Media::AudioFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IAudioMediaFrame)->GetAudioFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IBufferMediaFrame<D>::FrameReference() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IBufferMediaFrame)->get_FrameReference(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Capture_Frames_IBufferMediaFrame<D>::Buffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IBufferMediaFrame)->get_Buffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::FrameReference() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame)->get_FrameReference(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrame consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::VideoMediaFrame() const
{
    Windows::Media::Capture::Frames::VideoMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame)->get_VideoMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::DepthMediaFrameFormat consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::DepthFormat() const
{
    Windows::Media::Capture::Frames::DepthMediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame)->get_DepthFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::TryCreateCoordinateMapper(Windows::Media::Devices::Core::CameraIntrinsics const& cameraIntrinsics, Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame)->TryCreateCoordinateMapper(get_abi(cameraIntrinsics), get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_Frames_IDepthMediaFrame2<D>::MaxReliableDepth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame2)->get_MaxReliableDepth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_Frames_IDepthMediaFrame2<D>::MinReliableDepth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrame2)->get_MinReliableDepth(&value));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrameFormat consume_Windows_Media_Capture_Frames_IDepthMediaFrameFormat<D>::VideoFormat() const
{
    Windows::Media::Capture::Frames::VideoMediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrameFormat)->get_VideoFormat(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Media_Capture_Frames_IDepthMediaFrameFormat<D>::DepthScaleInMeters() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IDepthMediaFrameFormat)->get_DepthScaleInMeters(&value));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::FrameReference() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_FrameReference(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrame consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::VideoMediaFrame() const
{
    Windows::Media::Capture::Frames::VideoMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_VideoMediaFrame(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::IsIlluminated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_IsIlluminated(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::MajorType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat)->get_MajorType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::Subtype() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat)->get_Subtype(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::FrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat)->get_FrameRate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrameFormat consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::VideoFormat() const
{
    Windows::Media::Capture::Frames::VideoMediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat)->get_VideoFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::AudioEncodingProperties consume_Windows_Media_Capture_Frames_IMediaFrameFormat2<D>::AudioEncodingProperties() const
{
    Windows::Media::MediaProperties::AudioEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameFormat2)->get_AudioEncodingProperties(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameReader, Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader)->add_FrameArrived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived_revoker consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameReader, Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
}

template <typename D> void consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader)->remove_FrameArrived(get_abi(token)));
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::TryAcquireLatestFrame() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader)->TryAcquireLatestFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReaderStartStatus> consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReaderStartStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader)->StopAsync(put_abi(action)));
    return action;
}

template <typename D> void consume_Windows_Media_Capture_Frames_IMediaFrameReader2<D>::AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader2)->put_AcquisitionMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode consume_Windows_Media_Capture_Frames_IMediaFrameReader2<D>::AcquisitionMode() const
{
    Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReader2)->get_AcquisitionMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceKind consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::SourceKind() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_SourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameFormat consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Format() const
{
    Windows::Media::Capture::Frames::MediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_Format(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::SystemRelativeTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_SystemRelativeTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::BufferMediaFrame consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::BufferMediaFrame() const
{
    Windows::Media::Capture::Frames::BufferMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_BufferMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrame consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::VideoMediaFrame() const
{
    Windows::Media::Capture::Frames::VideoMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_VideoMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::AudioMediaFrame consume_Windows_Media_Capture_Frames_IMediaFrameReference2<D>::AudioMediaFrame() const
{
    Windows::Media::Capture::Frames::AudioMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameReference2)->get_AudioMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceInfo consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::Info() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->get_Info(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceController consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::Controller() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->get_Controller(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameFormat> consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::SupportedFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->get_SupportedFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameFormat consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::CurrentFormat() const
{
    Windows::Media::Capture::Frames::MediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->get_CurrentFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::SetFormatAsync(Windows::Media::Capture::Frames::MediaFrameFormat const& format) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->SetFormatAsync(get_abi(format), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameSource, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->add_FormatChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged_revoker consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameSource, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, FormatChanged_revoker>(this, FormatChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->remove_FormatChanged(get_abi(token)));
}

template <typename D> Windows::Media::Devices::Core::CameraIntrinsics consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::TryGetCameraIntrinsics(Windows::Media::Capture::Frames::MediaFrameFormat const& format) const
{
    Windows::Media::Devices::Core::CameraIntrinsics value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSource)->TryGetCameraIntrinsics(get_abi(format), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::GetPropertyAsync(param::hstring const& propertyId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController)->GetPropertyAsync(get_abi(propertyId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus> consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::SetPropertyAsync(param::hstring const& propertyId, Windows::Foundation::IInspectable const& propertyValue) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController)->SetPropertyAsync(get_abi(propertyId), get_abi(propertyValue), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceController consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::VideoDeviceController() const
{
    Windows::Media::Devices::VideoDeviceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController)->get_VideoDeviceController(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> consume_Windows_Media_Capture_Frames_IMediaFrameSourceController2<D>::GetPropertyByExtendedIdAsync(array_view<uint8_t const> extendedPropertyId, optional<uint32_t> const& maxPropertyValueSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController2)->GetPropertyByExtendedIdAsync(extendedPropertyId.size(), get_abi(extendedPropertyId), get_abi(maxPropertyValueSize), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus> consume_Windows_Media_Capture_Frames_IMediaFrameSourceController2<D>::SetPropertyByExtendedIdAsync(array_view<uint8_t const> extendedPropertyId, array_view<uint8_t const> propertyValue) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController2)->SetPropertyByExtendedIdAsync(extendedPropertyId.size(), get_abi(extendedPropertyId), propertyValue.size(), get_abi(propertyValue), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Devices::AudioDeviceController consume_Windows_Media_Capture_Frames_IMediaFrameSourceController3<D>::AudioDeviceController() const
{
    Windows::Media::Devices::AudioDeviceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceController3)->get_AudioDeviceController(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus consume_Windows_Media_Capture_Frames_IMediaFrameSourceGetPropertyResult<D>::Status() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Capture_Frames_IMediaFrameSourceGetPropertyResult<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo> consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::SourceInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_SourceInfos(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceGroup>> consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceGroup>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->FindAllAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGroup> consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::FromIdAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->FromIdAsync(get_abi(id), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::MediaStreamType consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::MediaStreamType() const
{
    Windows::Media::Capture::MediaStreamType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_MediaStreamType(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceKind consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::SourceKind() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_SourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceGroup consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::SourceGroup() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_SourceGroup(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo2<D>::ProfileId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo2)->get_ProfileId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo2<D>::VideoProfileMediaDescription() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMediaFrameSourceInfo2)->get_VideoProfileMediaDescription(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->add_FrameArrived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived_revoker consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
}

template <typename D> void consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->remove_FrameArrived(get_abi(token)));
}

template <typename D> Windows::Media::Capture::Frames::MultiSourceMediaFrameReference consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::TryAcquireLatestFrame() const
{
    Windows::Media::Capture::Frames::MultiSourceMediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->TryAcquireLatestFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus> consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->StopAsync(put_abi(action)));
    return action;
}

template <typename D> void consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader2<D>::AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2)->put_AcquisitionMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader2<D>::AcquisitionMode() const
{
    Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2)->get_AcquisitionMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReference<D>::TryGetFrameReferenceBySourceId(param::hstring const& sourceId) const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference)->TryGetFrameReferenceBySourceId(get_abi(sourceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameReference consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::FrameReference() const
{
    Windows::Media::Capture::Frames::MediaFrameReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_FrameReference(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::VideoMediaFrameFormat consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::VideoFormat() const
{
    Windows::Media::Capture::Frames::VideoMediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_VideoFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::SoftwareBitmap() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_SoftwareBitmap(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::Direct3DSurface() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_Direct3DSurface(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::CameraIntrinsics consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::CameraIntrinsics() const
{
    Windows::Media::Devices::Core::CameraIntrinsics value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_CameraIntrinsics(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::InfraredMediaFrame consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::InfraredMediaFrame() const
{
    Windows::Media::Capture::Frames::InfraredMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_InfraredMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::DepthMediaFrame consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::DepthMediaFrame() const
{
    Windows::Media::Capture::Frames::DepthMediaFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->get_DepthMediaFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::GetVideoFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrame)->GetVideoFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameFormat consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::MediaFrameFormat() const
{
    Windows::Media::Capture::Frames::MediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_MediaFrameFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::Frames::DepthMediaFrameFormat consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::DepthFormat() const
{
    Windows::Media::Capture::Frames::DepthMediaFrameFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_DepthFormat(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_Height(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IAudioMediaFrame> : produce_base<D, Windows::Media::Capture::Frames::IAudioMediaFrame>
{
    int32_t WINRT_CALL get_FrameReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameReference, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().AudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAudioFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAudioFrame, WINRT_WRAP(Windows::Media::AudioFrame));
            *value = detach_from<Windows::Media::AudioFrame>(this->shim().GetAudioFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IBufferMediaFrame> : produce_base<D, Windows::Media::Capture::Frames::IBufferMediaFrame>
{
    int32_t WINRT_CALL get_FrameReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameReference, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
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
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IDepthMediaFrame> : produce_base<D, Windows::Media::Capture::Frames::IDepthMediaFrame>
{
    int32_t WINRT_CALL get_FrameReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameReference, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepthFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepthFormat, WINRT_WRAP(Windows::Media::Capture::Frames::DepthMediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::DepthMediaFrameFormat>(this->shim().DepthFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateCoordinateMapper(void* cameraIntrinsics, void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateCoordinateMapper, WINRT_WRAP(Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper), Windows::Media::Devices::Core::CameraIntrinsics const&, Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper>(this->shim().TryCreateCoordinateMapper(*reinterpret_cast<Windows::Media::Devices::Core::CameraIntrinsics const*>(&cameraIntrinsics), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IDepthMediaFrame2> : produce_base<D, Windows::Media::Capture::Frames::IDepthMediaFrame2>
{
    int32_t WINRT_CALL get_MaxReliableDepth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxReliableDepth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxReliableDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinReliableDepth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinReliableDepth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinReliableDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IDepthMediaFrameFormat> : produce_base<D, Windows::Media::Capture::Frames::IDepthMediaFrameFormat>
{
    int32_t WINRT_CALL get_VideoFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormat, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepthScaleInMeters(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepthScaleInMeters, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DepthScaleInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IInfraredMediaFrame> : produce_base<D, Windows::Media::Capture::Frames::IInfraredMediaFrame>
{
    int32_t WINRT_CALL get_FrameReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameReference, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIlluminated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIlluminated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIlluminated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameFormat> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameFormat>
{
    int32_t WINRT_CALL get_MajorType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MajorType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MajorType());
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

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormat, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameFormat2> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameFormat2>
{
    int32_t WINRT_CALL get_AudioEncodingProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingProperties, WINRT_WRAP(Windows::Media::MediaProperties::AudioEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().AudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameReader> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameReader>
{
    int32_t WINRT_CALL add_FrameArrived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameReader, Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameReader, Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL TryAcquireLatestFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireLatestFrame, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().TryAcquireLatestFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReaderStartStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReaderStartStatus>>(this->shim().StartAsync());
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
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameReader2> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameReader2>
{
    int32_t WINRT_CALL put_AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionMode, WINRT_WRAP(void), Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const&);
            this->shim().AcquisitionMode(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionMode, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode>(this->shim().AcquisitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameReference> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameReference>
{
    int32_t WINRT_CALL get_SourceKind(Windows::Media::Capture::Frames::MediaFrameSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceKind, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceKind));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceKind>(this->shim().SourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Format(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemRelativeTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemRelativeTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().SystemRelativeTime());
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

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::BufferMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::BufferMediaFrame>(this->shim().BufferMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSystem, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem));
            *value = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameReference2> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameReference2>
{
    int32_t WINRT_CALL get_AudioMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::AudioMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::AudioMediaFrame>(this->shim().AudioMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSource> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSource>
{
    int32_t WINRT_CALL get_Info(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Info, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceInfo));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceInfo>(this->shim().Info());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Controller(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceController));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameFormat>>(this->shim().SupportedFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentFormat, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().CurrentFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFormatAsync(void* format, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFormatAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::Frames::MediaFrameFormat const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetFormatAsync(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FormatChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormatChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameSource, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().FormatChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MediaFrameSource, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FormatChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FormatChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FormatChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL TryGetCameraIntrinsics(void* format, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetCameraIntrinsics, WINRT_WRAP(Windows::Media::Devices::Core::CameraIntrinsics), Windows::Media::Capture::Frames::MediaFrameFormat const&);
            *value = detach_from<Windows::Media::Devices::Core::CameraIntrinsics>(this->shim().TryGetCameraIntrinsics(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceController> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceController>
{
    int32_t WINRT_CALL GetPropertyAsync(void* propertyId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>>(this->shim().GetPropertyAsync(*reinterpret_cast<hstring const*>(&propertyId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyAsync(void* propertyId, void* propertyValue, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>), hstring const, Windows::Foundation::IInspectable const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>>(this->shim().SetPropertyAsync(*reinterpret_cast<hstring const*>(&propertyId), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&propertyValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoDeviceController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceController, WINRT_WRAP(Windows::Media::Devices::VideoDeviceController));
            *value = detach_from<Windows::Media::Devices::VideoDeviceController>(this->shim().VideoDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceController2> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceController2>
{
    int32_t WINRT_CALL GetPropertyByExtendedIdAsync(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, void* maxPropertyValueSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertyByExtendedIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>), array_view<uint8_t const>, Windows::Foundation::IReference<uint32_t> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>>(this->shim().GetPropertyByExtendedIdAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), *reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&maxPropertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyByExtendedIdAsync(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, uint32_t __propertyValueSize, uint8_t* propertyValue, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyByExtendedIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>), array_view<uint8_t const>, array_view<uint8_t const>);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>>(this->shim().SetPropertyByExtendedIdAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(propertyValue), reinterpret_cast<uint8_t const *>(propertyValue) + __propertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceController3> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceController3>
{
    int32_t WINRT_CALL get_AudioDeviceController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceController, WINRT_WRAP(Windows::Media::Devices::AudioDeviceController));
            *value = detach_from<Windows::Media::Devices::AudioDeviceController>(this->shim().AudioDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult>
{
    int32_t WINRT_CALL get_Status(Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceGroup> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceGroup>
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

    int32_t WINRT_CALL get_SourceInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo>>(this->shim().SourceInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics>
{
    int32_t WINRT_CALL FindAllAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceGroup>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceGroup>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* id, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGroup>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGroup>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceInfo> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceInfo>
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

    int32_t WINRT_CALL get_MediaStreamType(Windows::Media::Capture::MediaStreamType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaStreamType, WINRT_WRAP(Windows::Media::Capture::MediaStreamType));
            *value = detach_from<Windows::Media::Capture::MediaStreamType>(this->shim().MediaStreamType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceKind(Windows::Media::Capture::Frames::MediaFrameSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceKind, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceKind));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceKind>(this->shim().SourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceGroup, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceGroup));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceGroup>(this->shim().SourceGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSystem, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem));
            *value = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMediaFrameSourceInfo2> : produce_base<D, Windows::Media::Capture::Frames::IMediaFrameSourceInfo2>
{
    int32_t WINRT_CALL get_ProfileId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProfileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoProfileMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProfileMediaDescription, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().VideoProfileMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs> : produce_base<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader> : produce_base<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader>
{
    int32_t WINRT_CALL add_FrameArrived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL TryAcquireLatestFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireLatestFrame, WINRT_WRAP(Windows::Media::Capture::Frames::MultiSourceMediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MultiSourceMediaFrameReference>(this->shim().TryAcquireLatestFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus>>(this->shim().StartAsync());
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
struct produce<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2> : produce_base<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2>
{
    int32_t WINRT_CALL put_AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionMode, WINRT_WRAP(void), Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const&);
            this->shim().AcquisitionMode(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcquisitionMode(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionMode, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode>(this->shim().AcquisitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference> : produce_base<D, Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference>
{
    int32_t WINRT_CALL TryGetFrameReferenceBySourceId(void* sourceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetFrameReferenceBySourceId, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference), hstring const&);
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().TryGetFrameReferenceBySourceId(*reinterpret_cast<hstring const*>(&sourceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IVideoMediaFrame> : produce_base<D, Windows::Media::Capture::Frames::IVideoMediaFrame>
{
    int32_t WINRT_CALL get_FrameReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameReference, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameReference));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFormat, WINRT_WRAP(Windows::Media::Capture::Frames::VideoMediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
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

    int32_t WINRT_CALL get_Direct3DSurface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3DSurface, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3DSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraIntrinsics(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraIntrinsics, WINRT_WRAP(Windows::Media::Devices::Core::CameraIntrinsics));
            *value = detach_from<Windows::Media::Devices::Core::CameraIntrinsics>(this->shim().CameraIntrinsics());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InfraredMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InfraredMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::InfraredMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::InfraredMediaFrame>(this->shim().InfraredMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepthMediaFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepthMediaFrame, WINRT_WRAP(Windows::Media::Capture::Frames::DepthMediaFrame));
            *value = detach_from<Windows::Media::Capture::Frames::DepthMediaFrame>(this->shim().DepthMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVideoFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().GetVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::Frames::IVideoMediaFrameFormat> : produce_base<D, Windows::Media::Capture::Frames::IVideoMediaFrameFormat>
{
    int32_t WINRT_CALL get_MediaFrameFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaFrameFormat, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().MediaFrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepthFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepthFormat, WINRT_WRAP(Windows::Media::Capture::Frames::DepthMediaFrameFormat));
            *value = detach_from<Windows::Media::Capture::Frames::DepthMediaFrameFormat>(this->shim().DepthFormat());
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

}

WINRT_EXPORT namespace winrt::Windows::Media::Capture::Frames {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceGroup>> MediaFrameSourceGroup::FindAllAsync()
{
    return impl::call_factory<MediaFrameSourceGroup, Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameSourceGroup> MediaFrameSourceGroup::FromIdAsync(param::hstring const& id)
{
    return impl::call_factory<MediaFrameSourceGroup, Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics>([&](auto&& f) { return f.FromIdAsync(id); });
}

inline hstring MediaFrameSourceGroup::GetDeviceSelector()
{
    return impl::call_factory<MediaFrameSourceGroup, Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Capture::Frames::IAudioMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IAudioMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IBufferMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IBufferMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameReader> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReader2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameReader2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReference> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameReference> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReference2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameReference2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSource> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSource> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IVideoMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IVideoMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::AudioMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::AudioMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::BufferMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::BufferMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::DepthMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::DepthMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::InfraredMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::InfraredMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameFormat> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameReader> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameReference> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameReference> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSource> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameSource> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceController> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameSourceController> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::VideoMediaFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::VideoMediaFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat> : winrt::impl::hash_base<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat> {};

}
