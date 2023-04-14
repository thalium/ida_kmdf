// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/Windows.Media.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::FocalLength() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_FocalLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::PrincipalPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_PrincipalPoint(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::RadialDistortion() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_RadialDistortion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::TangentialDistortion() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_TangentialDistortion(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::ImageWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_ImageWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::ImageHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->get_ImageHeight(&value));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::ProjectOntoFrame(Windows::Foundation::Numerics::float3 const& coordinate) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->ProjectOntoFrame(get_abi(coordinate), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::UnprojectAtUnitDepth(Windows::Foundation::Point const& pixelCoordinate) const
{
    Windows::Foundation::Numerics::float2 result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->UnprojectAtUnitDepth(get_abi(pixelCoordinate), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::ProjectManyOntoFrame(array_view<Windows::Foundation::Numerics::float3 const> coordinates, array_view<Windows::Foundation::Point> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->ProjectManyOntoFrame(coordinates.size(), get_abi(coordinates), results.size(), get_abi(results)));
}

template <typename D> void consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>::UnprojectPixelsAtUnitDepth(array_view<Windows::Foundation::Point const> pixelCoordinates, array_view<Windows::Foundation::Numerics::float2> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics)->UnprojectPixelsAtUnitDepth(pixelCoordinates.size(), get_abi(pixelCoordinates), results.size(), get_abi(results)));
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>::UndistortedProjectionTransform() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics2)->get_UndistortedProjectionTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>::DistortPoint(Windows::Foundation::Point const& input) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics2)->DistortPoint(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>::DistortPoints(array_view<Windows::Foundation::Point const> inputs, array_view<Windows::Foundation::Point> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics2)->DistortPoints(inputs.size(), get_abi(inputs), results.size(), get_abi(results)));
}

template <typename D> Windows::Foundation::Point consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>::UndistortPoint(Windows::Foundation::Point const& input) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics2)->UndistortPoint(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>::UndistortPoints(array_view<Windows::Foundation::Point const> inputs, array_view<Windows::Foundation::Point> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsics2)->UndistortPoints(inputs.size(), get_abi(inputs), results.size(), get_abi(results)));
}

template <typename D> Windows::Media::Devices::Core::CameraIntrinsics consume_Windows_Media_Devices_Core_ICameraIntrinsicsFactory<D>::Create(Windows::Foundation::Numerics::float2 const& focalLength, Windows::Foundation::Numerics::float2 const& principalPoint, Windows::Foundation::Numerics::float3 const& radialDistortion, Windows::Foundation::Numerics::float2 const& tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight) const
{
    Windows::Media::Devices::Core::CameraIntrinsics result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::ICameraIntrinsicsFactory)->Create(get_abi(focalLength), get_abi(principalPoint), get_abi(radialDistortion), get_abi(tangentialDistortion), imageWidth, imageHeight, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper<D>::UnprojectPoint(Windows::Foundation::Point const& sourcePoint, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem) const
{
    Windows::Foundation::Numerics::float3 result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper)->UnprojectPoint(get_abi(sourcePoint), get_abi(targetCoordinateSystem), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper<D>::UnprojectPoints(array_view<Windows::Foundation::Point const> sourcePoints, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, array_view<Windows::Foundation::Numerics::float3> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper)->UnprojectPoints(sourcePoints.size(), get_abi(sourcePoints), get_abi(targetCoordinateSystem), results.size(), get_abi(results)));
}

template <typename D> Windows::Foundation::Point consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper<D>::MapPoint(Windows::Foundation::Point const& sourcePoint, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, Windows::Media::Devices::Core::CameraIntrinsics const& targetCameraIntrinsics) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper)->MapPoint(get_abi(sourcePoint), get_abi(targetCoordinateSystem), get_abi(targetCameraIntrinsics), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper<D>::MapPoints(array_view<Windows::Foundation::Point const> sourcePoints, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, Windows::Media::Devices::Core::CameraIntrinsics const& targetCameraIntrinsics, array_view<Windows::Foundation::Point> results) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper)->MapPoints(sourcePoints.size(), get_abi(sourcePoints), get_abi(targetCoordinateSystem), get_abi(targetCameraIntrinsics), results.size(), get_abi(results)));
}

template <typename D> Windows::Media::Devices::Core::FrameExposureCapabilities consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>::Exposure() const
{
    Windows::Media::Devices::Core::FrameExposureCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities)->get_Exposure(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameExposureCompensationCapabilities consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>::ExposureCompensation() const
{
    Windows::Media::Devices::Core::FrameExposureCompensationCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities)->get_ExposureCompensation(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameIsoSpeedCapabilities consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>::IsoSpeed() const
{
    Windows::Media::Devices::Core::FrameIsoSpeedCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities)->get_IsoSpeed(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameFocusCapabilities consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>::Focus() const
{
    Windows::Media::Devices::Core::FrameFocusCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities)->get_Focus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>::PhotoConfirmationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities)->get_PhotoConfirmationSupported(&value));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameFlashCapabilities consume_Windows_Media_Devices_Core_IFrameControlCapabilities2<D>::Flash() const
{
    Windows::Media::Devices::Core::FrameFlashCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameControlCapabilities2)->get_Flash(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameExposureControl consume_Windows_Media_Devices_Core_IFrameController<D>::ExposureControl() const
{
    Windows::Media::Devices::Core::FrameExposureControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->get_ExposureControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameExposureCompensationControl consume_Windows_Media_Devices_Core_IFrameController<D>::ExposureCompensationControl() const
{
    Windows::Media::Devices::Core::FrameExposureCompensationControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->get_ExposureCompensationControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameIsoSpeedControl consume_Windows_Media_Devices_Core_IFrameController<D>::IsoSpeedControl() const
{
    Windows::Media::Devices::Core::FrameIsoSpeedControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->get_IsoSpeedControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameFocusControl consume_Windows_Media_Devices_Core_IFrameController<D>::FocusControl() const
{
    Windows::Media::Devices::Core::FrameFocusControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->get_FocusControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Media_Devices_Core_IFrameController<D>::PhotoConfirmationEnabled() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->get_PhotoConfirmationEnabled(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameController<D>::PhotoConfirmationEnabled(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController)->put_PhotoConfirmationEnabled(get_abi(value)));
}

template <typename D> Windows::Media::Devices::Core::FrameFlashControl consume_Windows_Media_Devices_Core_IFrameController2<D>::FlashControl() const
{
    Windows::Media::Devices::Core::FrameFlashControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameController2)->get_FlashControl(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameExposureCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_Core_IFrameExposureCapabilities<D>::Min() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCapabilities)->get_Min(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_Core_IFrameExposureCapabilities<D>::Max() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCapabilities)->get_Max(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Devices_Core_IFrameExposureCapabilities<D>::Step() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCapabilities)->get_Step(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities<D>::Min() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities)->get_Min(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities<D>::Max() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities)->get_Max(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities<D>::Step() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities)->get_Step(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_Media_Devices_Core_IFrameExposureCompensationControl<D>::Value() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameExposureCompensationControl<D>::Value(optional<float> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureCompensationControl)->put_Value(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameExposureControl<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureControl)->get_Auto(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameExposureControl<D>::Auto(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureControl)->put_Auto(value));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Devices_Core_IFrameExposureControl<D>::Value() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameExposureControl<D>::Value(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameExposureControl)->put_Value(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFlashCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFlashCapabilities<D>::RedEyeReductionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashCapabilities)->get_RedEyeReductionSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFlashCapabilities<D>::PowerSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashCapabilities)->get_PowerSupported(&value));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameFlashMode consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::Mode() const
{
    Windows::Media::Devices::Core::FrameFlashMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::Mode(Windows::Media::Devices::Core::FrameFlashMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->put_Mode(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->get_Auto(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::Auto(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->put_Auto(value));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::RedEyeReduction() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->get_RedEyeReduction(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::RedEyeReduction(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->put_RedEyeReduction(value));
}

template <typename D> float consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::PowerPercent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->get_PowerPercent(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameFlashControl<D>::PowerPercent(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFlashControl)->put_PowerPercent(value));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameFocusCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameFocusCapabilities<D>::Min() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusCapabilities)->get_Min(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameFocusCapabilities<D>::Max() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusCapabilities)->get_Max(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameFocusCapabilities<D>::Step() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusCapabilities)->get_Step(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Devices_Core_IFrameFocusControl<D>::Value() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameFocusControl<D>::Value(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameFocusControl)->put_Value(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities)->get_Supported(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities<D>::Min() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities)->get_Min(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities<D>::Max() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities)->get_Max(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities<D>::Step() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities)->get_Step(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl<D>::Auto() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedControl)->get_Auto(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl<D>::Auto(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedControl)->put_Auto(value));
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl<D>::Value() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedControl)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl<D>::Value(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IFrameIsoSpeedControl)->put_Value(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::Supported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->get_Supported(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::MaxPhotosPerSecond() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->get_MaxPhotosPerSecond(&value));
    return value;
}

template <typename D> float consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::PhotosPerSecondLimit() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->get_PhotosPerSecondLimit(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::PhotosPerSecondLimit(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->put_PhotosPerSecondLimit(value));
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::GetHighestConcurrentFrameRate(Windows::Media::MediaProperties::IMediaEncodingProperties const& captureProperties) const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->GetHighestConcurrentFrameRate(get_abi(captureProperties), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::GetCurrentFrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->GetCurrentFrameRate(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::Core::FrameControlCapabilities consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::FrameCapabilities() const
{
    Windows::Media::Devices::Core::FrameControlCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->get_FrameCapabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Media::Devices::Core::FrameController> consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>::DesiredFrameControllers() const
{
    Windows::Foundation::Collections::IVector<Windows::Media::Devices::Core::FrameController> items{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Devices::Core::IVariablePhotoSequenceController)->get_DesiredFrameControllers(put_abi(items)));
    return items;
}

template <typename D>
struct produce<D, Windows::Media::Devices::Core::ICameraIntrinsics> : produce_base<D, Windows::Media::Devices::Core::ICameraIntrinsics>
{
    int32_t WINRT_CALL get_FocalLength(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocalLength, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().FocalLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrincipalPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrincipalPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().PrincipalPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RadialDistortion(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RadialDistortion, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().RadialDistortion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TangentialDistortion(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TangentialDistortion, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().TangentialDistortion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ImageWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ImageHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProjectOntoFrame(Windows::Foundation::Numerics::float3 coordinate, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectOntoFrame, WINRT_WRAP(Windows::Foundation::Point), Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().ProjectOntoFrame(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&coordinate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprojectAtUnitDepth(Windows::Foundation::Point pixelCoordinate, Windows::Foundation::Numerics::float2* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprojectAtUnitDepth, WINRT_WRAP(Windows::Foundation::Numerics::float2), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Numerics::float2>(this->shim().UnprojectAtUnitDepth(*reinterpret_cast<Windows::Foundation::Point const*>(&pixelCoordinate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProjectManyOntoFrame(uint32_t __coordinatesSize, Windows::Foundation::Numerics::float3* coordinates, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectManyOntoFrame, WINRT_WRAP(void), array_view<Windows::Foundation::Numerics::float3 const>, array_view<Windows::Foundation::Point>);
            this->shim().ProjectManyOntoFrame(array_view<Windows::Foundation::Numerics::float3 const>(reinterpret_cast<Windows::Foundation::Numerics::float3 const *>(coordinates), reinterpret_cast<Windows::Foundation::Numerics::float3 const *>(coordinates) + __coordinatesSize), array_view<Windows::Foundation::Point>(reinterpret_cast<Windows::Foundation::Point*>(results), reinterpret_cast<Windows::Foundation::Point*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprojectPixelsAtUnitDepth(uint32_t __pixelCoordinatesSize, Windows::Foundation::Point* pixelCoordinates, uint32_t __resultsSize, Windows::Foundation::Numerics::float2* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprojectPixelsAtUnitDepth, WINRT_WRAP(void), array_view<Windows::Foundation::Point const>, array_view<Windows::Foundation::Numerics::float2>);
            this->shim().UnprojectPixelsAtUnitDepth(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(pixelCoordinates), reinterpret_cast<Windows::Foundation::Point const *>(pixelCoordinates) + __pixelCoordinatesSize), array_view<Windows::Foundation::Numerics::float2>(reinterpret_cast<Windows::Foundation::Numerics::float2*>(results), reinterpret_cast<Windows::Foundation::Numerics::float2*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::ICameraIntrinsics2> : produce_base<D, Windows::Media::Devices::Core::ICameraIntrinsics2>
{
    int32_t WINRT_CALL get_UndistortedProjectionTransform(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndistortedProjectionTransform, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().UndistortedProjectionTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DistortPoint(Windows::Foundation::Point input, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistortPoint, WINRT_WRAP(Windows::Foundation::Point), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().DistortPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DistortPoints(uint32_t __inputsSize, Windows::Foundation::Point* inputs, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistortPoints, WINRT_WRAP(void), array_view<Windows::Foundation::Point const>, array_view<Windows::Foundation::Point>);
            this->shim().DistortPoints(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(inputs), reinterpret_cast<Windows::Foundation::Point const *>(inputs) + __inputsSize), array_view<Windows::Foundation::Point>(reinterpret_cast<Windows::Foundation::Point*>(results), reinterpret_cast<Windows::Foundation::Point*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UndistortPoint(Windows::Foundation::Point input, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndistortPoint, WINRT_WRAP(Windows::Foundation::Point), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().UndistortPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UndistortPoints(uint32_t __inputsSize, Windows::Foundation::Point* inputs, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndistortPoints, WINRT_WRAP(void), array_view<Windows::Foundation::Point const>, array_view<Windows::Foundation::Point>);
            this->shim().UndistortPoints(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(inputs), reinterpret_cast<Windows::Foundation::Point const *>(inputs) + __inputsSize), array_view<Windows::Foundation::Point>(reinterpret_cast<Windows::Foundation::Point*>(results), reinterpret_cast<Windows::Foundation::Point*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::ICameraIntrinsicsFactory> : produce_base<D, Windows::Media::Devices::Core::ICameraIntrinsicsFactory>
{
    int32_t WINRT_CALL Create(Windows::Foundation::Numerics::float2 focalLength, Windows::Foundation::Numerics::float2 principalPoint, Windows::Foundation::Numerics::float3 radialDistortion, Windows::Foundation::Numerics::float2 tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::Devices::Core::CameraIntrinsics), Windows::Foundation::Numerics::float2 const&, Windows::Foundation::Numerics::float2 const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float2 const&, uint32_t, uint32_t);
            *result = detach_from<Windows::Media::Devices::Core::CameraIntrinsics>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&focalLength), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&principalPoint), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&radialDistortion), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&tangentialDistortion), imageWidth, imageHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper> : produce_base<D, Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper>
{
    int32_t WINRT_CALL UnprojectPoint(Windows::Foundation::Point sourcePoint, void* targetCoordinateSystem, Windows::Foundation::Numerics::float3* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprojectPoint, WINRT_WRAP(Windows::Foundation::Numerics::float3), Windows::Foundation::Point const&, Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *result = detach_from<Windows::Foundation::Numerics::float3>(this->shim().UnprojectPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&sourcePoint), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&targetCoordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnprojectPoints(uint32_t __sourcePointsSize, Windows::Foundation::Point* sourcePoints, void* targetCoordinateSystem, uint32_t __resultsSize, Windows::Foundation::Numerics::float3* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnprojectPoints, WINRT_WRAP(void), array_view<Windows::Foundation::Point const>, Windows::Perception::Spatial::SpatialCoordinateSystem const&, array_view<Windows::Foundation::Numerics::float3>);
            this->shim().UnprojectPoints(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(sourcePoints), reinterpret_cast<Windows::Foundation::Point const *>(sourcePoints) + __sourcePointsSize), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&targetCoordinateSystem), array_view<Windows::Foundation::Numerics::float3>(reinterpret_cast<Windows::Foundation::Numerics::float3*>(results), reinterpret_cast<Windows::Foundation::Numerics::float3*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MapPoint(Windows::Foundation::Point sourcePoint, void* targetCoordinateSystem, void* targetCameraIntrinsics, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapPoint, WINRT_WRAP(Windows::Foundation::Point), Windows::Foundation::Point const&, Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Media::Devices::Core::CameraIntrinsics const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().MapPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&sourcePoint), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&targetCoordinateSystem), *reinterpret_cast<Windows::Media::Devices::Core::CameraIntrinsics const*>(&targetCameraIntrinsics)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MapPoints(uint32_t __sourcePointsSize, Windows::Foundation::Point* sourcePoints, void* targetCoordinateSystem, void* targetCameraIntrinsics, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapPoints, WINRT_WRAP(void), array_view<Windows::Foundation::Point const>, Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Media::Devices::Core::CameraIntrinsics const&, array_view<Windows::Foundation::Point>);
            this->shim().MapPoints(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(sourcePoints), reinterpret_cast<Windows::Foundation::Point const *>(sourcePoints) + __sourcePointsSize), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&targetCoordinateSystem), *reinterpret_cast<Windows::Media::Devices::Core::CameraIntrinsics const*>(&targetCameraIntrinsics), array_view<Windows::Foundation::Point>(reinterpret_cast<Windows::Foundation::Point*>(results), reinterpret_cast<Windows::Foundation::Point*>(results) + __resultsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameControlCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameControlCapabilities>
{
    int32_t WINRT_CALL get_Exposure(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exposure, WINRT_WRAP(Windows::Media::Devices::Core::FrameExposureCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameExposureCapabilities>(this->shim().Exposure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExposureCompensation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureCompensation, WINRT_WRAP(Windows::Media::Devices::Core::FrameExposureCompensationCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameExposureCompensationCapabilities>(this->shim().ExposureCompensation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoSpeed(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoSpeed, WINRT_WRAP(Windows::Media::Devices::Core::FrameIsoSpeedCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameIsoSpeedCapabilities>(this->shim().IsoSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Focus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Focus, WINRT_WRAP(Windows::Media::Devices::Core::FrameFocusCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameFocusCapabilities>(this->shim().Focus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoConfirmationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoConfirmationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PhotoConfirmationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameControlCapabilities2> : produce_base<D, Windows::Media::Devices::Core::IFrameControlCapabilities2>
{
    int32_t WINRT_CALL get_Flash(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flash, WINRT_WRAP(Windows::Media::Devices::Core::FrameFlashCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameFlashCapabilities>(this->shim().Flash());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameController> : produce_base<D, Windows::Media::Devices::Core::IFrameController>
{
    int32_t WINRT_CALL get_ExposureControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureControl, WINRT_WRAP(Windows::Media::Devices::Core::FrameExposureControl));
            *value = detach_from<Windows::Media::Devices::Core::FrameExposureControl>(this->shim().ExposureControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExposureCompensationControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureCompensationControl, WINRT_WRAP(Windows::Media::Devices::Core::FrameExposureCompensationControl));
            *value = detach_from<Windows::Media::Devices::Core::FrameExposureCompensationControl>(this->shim().ExposureCompensationControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoSpeedControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoSpeedControl, WINRT_WRAP(Windows::Media::Devices::Core::FrameIsoSpeedControl));
            *value = detach_from<Windows::Media::Devices::Core::FrameIsoSpeedControl>(this->shim().IsoSpeedControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusControl, WINRT_WRAP(Windows::Media::Devices::Core::FrameFocusControl));
            *value = detach_from<Windows::Media::Devices::Core::FrameFocusControl>(this->shim().FocusControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoConfirmationEnabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoConfirmationEnabled, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().PhotoConfirmationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhotoConfirmationEnabled(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoConfirmationEnabled, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().PhotoConfirmationEnabled(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameController2> : produce_base<D, Windows::Media::Devices::Core::IFrameController2>
{
    int32_t WINRT_CALL get_FlashControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlashControl, WINRT_WRAP(Windows::Media::Devices::Core::FrameFlashControl));
            *value = detach_from<Windows::Media::Devices::Core::FrameFlashControl>(this->shim().FlashControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameExposureCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameExposureCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameExposureCompensationControl> : produce_base<D, Windows::Media::Devices::Core::IFrameExposureCompensationControl>
{
    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IReference<float> const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IReference<float> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameExposureControl> : produce_base<D, Windows::Media::Devices::Core::IFrameExposureControl>
{
    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Auto(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(void), bool);
            this->shim().Auto(value);
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameFlashCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameFlashCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedEyeReductionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReductionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RedEyeReductionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PowerSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameFlashControl> : produce_base<D, Windows::Media::Devices::Core::IFrameFlashControl>
{
    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::Core::FrameFlashMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::Core::FrameFlashMode));
            *value = detach_from<Windows::Media::Devices::Core::FrameFlashMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Media::Devices::Core::FrameFlashMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Media::Devices::Core::FrameFlashMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Media::Devices::Core::FrameFlashMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Auto(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(void), bool);
            this->shim().Auto(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedEyeReduction(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReduction, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RedEyeReduction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RedEyeReduction(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedEyeReduction, WINRT_WRAP(void), bool);
            this->shim().RedEyeReduction(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerPercent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PowerPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PowerPercent(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerPercent, WINRT_WRAP(void), float);
            this->shim().PowerPercent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameFocusCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameFocusCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameFocusControl> : produce_base<D, Windows::Media::Devices::Core::IFrameFocusControl>
{
    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities> : produce_base<D, Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Step(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Step, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Step());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IFrameIsoSpeedControl> : produce_base<D, Windows::Media::Devices::Core::IFrameIsoSpeedControl>
{
    int32_t WINRT_CALL get_Auto(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Auto(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(void), bool);
            this->shim().Auto(value);
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Devices::Core::IVariablePhotoSequenceController> : produce_base<D, Windows::Media::Devices::Core::IVariablePhotoSequenceController>
{
    int32_t WINRT_CALL get_Supported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Supported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Supported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPhotosPerSecond(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPhotosPerSecond, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxPhotosPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosPerSecondLimit(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosPerSecondLimit, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PhotosPerSecondLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhotosPerSecondLimit(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosPerSecondLimit, WINRT_WRAP(void), float);
            this->shim().PhotosPerSecondLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHighestConcurrentFrameRate(void* captureProperties, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHighestConcurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio), Windows::Media::MediaProperties::IMediaEncodingProperties const&);
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetHighestConcurrentFrameRate(*reinterpret_cast<Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&captureProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentFrameRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().GetCurrentFrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameCapabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameCapabilities, WINRT_WRAP(Windows::Media::Devices::Core::FrameControlCapabilities));
            *value = detach_from<Windows::Media::Devices::Core::FrameControlCapabilities>(this->shim().FrameCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredFrameControllers(void** items) noexcept final
    {
        try
        {
            *items = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredFrameControllers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Media::Devices::Core::FrameController>));
            *items = detach_from<Windows::Foundation::Collections::IVector<Windows::Media::Devices::Core::FrameController>>(this->shim().DesiredFrameControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Devices::Core {

inline CameraIntrinsics::CameraIntrinsics(Windows::Foundation::Numerics::float2 const& focalLength, Windows::Foundation::Numerics::float2 const& principalPoint, Windows::Foundation::Numerics::float3 const& radialDistortion, Windows::Foundation::Numerics::float2 const& tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight) :
    CameraIntrinsics(impl::call_factory<CameraIntrinsics, Windows::Media::Devices::Core::ICameraIntrinsicsFactory>([&](auto&& f) { return f.Create(focalLength, principalPoint, radialDistortion, tangentialDistortion, imageWidth, imageHeight); }))
{}

inline FrameController::FrameController() :
    FrameController(impl::call_factory<FrameController>([](auto&& f) { return f.template ActivateInstance<FrameController>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Devices::Core::ICameraIntrinsics> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::ICameraIntrinsics> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::ICameraIntrinsics2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::ICameraIntrinsics2> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::ICameraIntrinsicsFactory> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::ICameraIntrinsicsFactory> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameControlCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameControlCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameControlCapabilities2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameControlCapabilities2> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameController> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameController2> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameController2> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameExposureCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameExposureCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameExposureCompensationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameExposureCompensationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameExposureControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameExposureControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameFlashCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameFlashCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameFlashControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameFlashControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameFocusCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameFocusCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameFocusControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameFocusControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IFrameIsoSpeedControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IFrameIsoSpeedControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::IVariablePhotoSequenceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::IVariablePhotoSequenceController> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::CameraIntrinsics> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::CameraIntrinsics> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameControlCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameControlCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameController> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameExposureCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameExposureCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameExposureCompensationCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameExposureCompensationCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameExposureCompensationControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameExposureCompensationControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameExposureControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameExposureControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameFlashCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameFlashCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameFlashControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameFlashControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameFocusCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameFocusCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameFocusControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameFocusControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameIsoSpeedCapabilities> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameIsoSpeedCapabilities> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::FrameIsoSpeedControl> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::FrameIsoSpeedControl> {};
template<> struct hash<winrt::Windows::Media::Devices::Core::VariablePhotoSequenceController> : winrt::impl::hash_base<winrt::Windows::Media::Devices::Core::VariablePhotoSequenceController> {};

}
