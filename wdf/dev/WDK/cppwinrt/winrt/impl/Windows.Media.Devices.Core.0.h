// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

struct IMediaEncodingProperties;
struct MediaRatio;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct SpatialCoordinateSystem;

}

WINRT_EXPORT namespace winrt::Windows::Media::Devices::Core {

enum class FrameFlashMode : int32_t
{
    Disable = 0,
    Enable = 1,
    Global = 2,
};

struct ICameraIntrinsics;
struct ICameraIntrinsics2;
struct ICameraIntrinsicsFactory;
struct IDepthCorrelatedCoordinateMapper;
struct IFrameControlCapabilities;
struct IFrameControlCapabilities2;
struct IFrameController;
struct IFrameController2;
struct IFrameExposureCapabilities;
struct IFrameExposureCompensationCapabilities;
struct IFrameExposureCompensationControl;
struct IFrameExposureControl;
struct IFrameFlashCapabilities;
struct IFrameFlashControl;
struct IFrameFocusCapabilities;
struct IFrameFocusControl;
struct IFrameIsoSpeedCapabilities;
struct IFrameIsoSpeedControl;
struct IVariablePhotoSequenceController;
struct CameraIntrinsics;
struct DepthCorrelatedCoordinateMapper;
struct FrameControlCapabilities;
struct FrameController;
struct FrameExposureCapabilities;
struct FrameExposureCompensationCapabilities;
struct FrameExposureCompensationControl;
struct FrameExposureControl;
struct FrameFlashCapabilities;
struct FrameFlashControl;
struct FrameFocusCapabilities;
struct FrameFocusControl;
struct FrameIsoSpeedCapabilities;
struct FrameIsoSpeedControl;
struct VariablePhotoSequenceController;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Devices::Core::ICameraIntrinsics>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::ICameraIntrinsics2>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::ICameraIntrinsicsFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameControlCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameControlCapabilities2>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameController>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameController2>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameExposureCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameExposureCompensationControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameExposureControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameFlashCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameFlashControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameFocusCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameFocusControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IFrameIsoSpeedControl>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::IVariablePhotoSequenceController>{ using type = interface_category; };
template <> struct category<Windows::Media::Devices::Core::CameraIntrinsics>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameControlCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameController>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameExposureCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameExposureCompensationCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameExposureCompensationControl>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameExposureControl>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameFlashCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameFlashControl>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameFocusCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameFocusControl>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameIsoSpeedCapabilities>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameIsoSpeedControl>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::VariablePhotoSequenceController>{ using type = class_category; };
template <> struct category<Windows::Media::Devices::Core::FrameFlashMode>{ using type = enum_category; };
template <> struct name<Windows::Media::Devices::Core::ICameraIntrinsics>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.ICameraIntrinsics" }; };
template <> struct name<Windows::Media::Devices::Core::ICameraIntrinsics2>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.ICameraIntrinsics2" }; };
template <> struct name<Windows::Media::Devices::Core::ICameraIntrinsicsFactory>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.ICameraIntrinsicsFactory" }; };
template <> struct name<Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IDepthCorrelatedCoordinateMapper" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameControlCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameControlCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameControlCapabilities2>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameControlCapabilities2" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameController>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameController" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameController2>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameController2" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameExposureCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameExposureCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameExposureCompensationCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameExposureCompensationControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameExposureCompensationControl" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameExposureControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameExposureControl" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameFlashCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameFlashCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameFlashControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameFlashControl" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameFocusCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameFocusCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameFocusControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameFocusControl" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameIsoSpeedCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::IFrameIsoSpeedControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IFrameIsoSpeedControl" }; };
template <> struct name<Windows::Media::Devices::Core::IVariablePhotoSequenceController>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.IVariablePhotoSequenceController" }; };
template <> struct name<Windows::Media::Devices::Core::CameraIntrinsics>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.CameraIntrinsics" }; };
template <> struct name<Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.DepthCorrelatedCoordinateMapper" }; };
template <> struct name<Windows::Media::Devices::Core::FrameControlCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameControlCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameController>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameController" }; };
template <> struct name<Windows::Media::Devices::Core::FrameExposureCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameExposureCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameExposureCompensationCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameExposureCompensationCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameExposureCompensationControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameExposureCompensationControl" }; };
template <> struct name<Windows::Media::Devices::Core::FrameExposureControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameExposureControl" }; };
template <> struct name<Windows::Media::Devices::Core::FrameFlashCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameFlashCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameFlashControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameFlashControl" }; };
template <> struct name<Windows::Media::Devices::Core::FrameFocusCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameFocusCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameFocusControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameFocusControl" }; };
template <> struct name<Windows::Media::Devices::Core::FrameIsoSpeedCapabilities>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameIsoSpeedCapabilities" }; };
template <> struct name<Windows::Media::Devices::Core::FrameIsoSpeedControl>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameIsoSpeedControl" }; };
template <> struct name<Windows::Media::Devices::Core::VariablePhotoSequenceController>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.VariablePhotoSequenceController" }; };
template <> struct name<Windows::Media::Devices::Core::FrameFlashMode>{ static constexpr auto & value{ L"Windows.Media.Devices.Core.FrameFlashMode" }; };
template <> struct guid_storage<Windows::Media::Devices::Core::ICameraIntrinsics>{ static constexpr guid value{ 0x0AA6ED32,0x6589,0x49DA,{ 0xAF,0xDE,0x59,0x42,0x70,0xCA,0x0A,0xAC } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::ICameraIntrinsics2>{ static constexpr guid value{ 0x0CDAA447,0x0798,0x4B4D,{ 0x83,0x9F,0xC5,0xEC,0x41,0x4D,0xB2,0x7A } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::ICameraIntrinsicsFactory>{ static constexpr guid value{ 0xC0DDC486,0x2132,0x4A34,{ 0xA6,0x59,0x9B,0xFE,0x2A,0x05,0x57,0x12 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper>{ static constexpr guid value{ 0xF95D89FB,0x8AF0,0x4CB0,{ 0x92,0x6D,0x69,0x68,0x66,0xE5,0x04,0x6A } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameControlCapabilities>{ static constexpr guid value{ 0xA8FFAE60,0x4E9E,0x4377,{ 0xA7,0x89,0xE2,0x4C,0x4A,0xE7,0xE5,0x44 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameControlCapabilities2>{ static constexpr guid value{ 0xCE9B0464,0x4730,0x440F,{ 0xBD,0x3E,0xEF,0xE8,0xA8,0xF2,0x30,0xA8 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameController>{ static constexpr guid value{ 0xC16459D9,0xBAEF,0x4052,{ 0x91,0x77,0x48,0xAF,0xF2,0xAF,0x75,0x22 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameController2>{ static constexpr guid value{ 0x00D3BC75,0xD87C,0x485B,{ 0x8A,0x09,0x5C,0x35,0x85,0x68,0xB4,0x27 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameExposureCapabilities>{ static constexpr guid value{ 0xBDBE9CE3,0x3985,0x4E72,{ 0x97,0xC2,0x05,0x90,0xD6,0x13,0x07,0xA1 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities>{ static constexpr guid value{ 0xB988A823,0x8065,0x41EE,{ 0xB0,0x4F,0x72,0x22,0x65,0x95,0x45,0x00 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameExposureCompensationControl>{ static constexpr guid value{ 0xE95896C9,0xF7F9,0x48CA,{ 0x85,0x91,0xA2,0x65,0x31,0xCB,0x15,0x78 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameExposureControl>{ static constexpr guid value{ 0xB1605A61,0xFFAF,0x4752,{ 0xB6,0x21,0xF5,0xB6,0xF1,0x17,0xF4,0x32 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameFlashCapabilities>{ static constexpr guid value{ 0xBB9341A2,0x5EBE,0x4F62,{ 0x82,0x23,0x0E,0x2B,0x05,0xBF,0xBB,0xD0 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameFlashControl>{ static constexpr guid value{ 0x75D5F6C7,0xBD45,0x4FAB,{ 0x93,0x75,0x45,0xAC,0x04,0xB3,0x32,0xC2 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameFocusCapabilities>{ static constexpr guid value{ 0x7B25CD58,0x01C0,0x4065,{ 0x9C,0x40,0xC1,0xA7,0x21,0x42,0x5C,0x1A } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameFocusControl>{ static constexpr guid value{ 0x272DF1D0,0xD912,0x4214,{ 0xA6,0x7B,0xE3,0x8A,0x8D,0x48,0xD8,0xC6 } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities>{ static constexpr guid value{ 0x16BDFF61,0x6DF6,0x4AC9,{ 0xB9,0x2A,0x9F,0x6E,0xCD,0x1A,0xD2,0xFA } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IFrameIsoSpeedControl>{ static constexpr guid value{ 0x1A03EFED,0x786A,0x4C75,{ 0xA5,0x57,0x7A,0xB9,0xA8,0x5F,0x58,0x8C } }; };
template <> struct guid_storage<Windows::Media::Devices::Core::IVariablePhotoSequenceController>{ static constexpr guid value{ 0x7FBFF880,0xED8C,0x43FD,{ 0xA7,0xC3,0xB3,0x58,0x09,0xE4,0x22,0x9A } }; };
template <> struct default_interface<Windows::Media::Devices::Core::CameraIntrinsics>{ using type = Windows::Media::Devices::Core::ICameraIntrinsics; };
template <> struct default_interface<Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper>{ using type = Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameControlCapabilities>{ using type = Windows::Media::Devices::Core::IFrameControlCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameController>{ using type = Windows::Media::Devices::Core::IFrameController; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameExposureCapabilities>{ using type = Windows::Media::Devices::Core::IFrameExposureCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameExposureCompensationCapabilities>{ using type = Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameExposureCompensationControl>{ using type = Windows::Media::Devices::Core::IFrameExposureCompensationControl; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameExposureControl>{ using type = Windows::Media::Devices::Core::IFrameExposureControl; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameFlashCapabilities>{ using type = Windows::Media::Devices::Core::IFrameFlashCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameFlashControl>{ using type = Windows::Media::Devices::Core::IFrameFlashControl; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameFocusCapabilities>{ using type = Windows::Media::Devices::Core::IFrameFocusCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameFocusControl>{ using type = Windows::Media::Devices::Core::IFrameFocusControl; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameIsoSpeedCapabilities>{ using type = Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities; };
template <> struct default_interface<Windows::Media::Devices::Core::FrameIsoSpeedControl>{ using type = Windows::Media::Devices::Core::IFrameIsoSpeedControl; };
template <> struct default_interface<Windows::Media::Devices::Core::VariablePhotoSequenceController>{ using type = Windows::Media::Devices::Core::IVariablePhotoSequenceController; };

template <> struct abi<Windows::Media::Devices::Core::ICameraIntrinsics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FocalLength(Windows::Foundation::Numerics::float2* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrincipalPoint(Windows::Foundation::Numerics::float2* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RadialDistortion(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TangentialDistortion(Windows::Foundation::Numerics::float2* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImageWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImageHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL ProjectOntoFrame(Windows::Foundation::Numerics::float3 coordinate, Windows::Foundation::Point* result) noexcept = 0;
    virtual int32_t WINRT_CALL UnprojectAtUnitDepth(Windows::Foundation::Point pixelCoordinate, Windows::Foundation::Numerics::float2* result) noexcept = 0;
    virtual int32_t WINRT_CALL ProjectManyOntoFrame(uint32_t __coordinatesSize, Windows::Foundation::Numerics::float3* coordinates, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept = 0;
    virtual int32_t WINRT_CALL UnprojectPixelsAtUnitDepth(uint32_t __pixelCoordinatesSize, Windows::Foundation::Point* pixelCoordinates, uint32_t __resultsSize, Windows::Foundation::Numerics::float2* results) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::ICameraIntrinsics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UndistortedProjectionTransform(Windows::Foundation::Numerics::float4x4* value) noexcept = 0;
    virtual int32_t WINRT_CALL DistortPoint(Windows::Foundation::Point input, Windows::Foundation::Point* result) noexcept = 0;
    virtual int32_t WINRT_CALL DistortPoints(uint32_t __inputsSize, Windows::Foundation::Point* inputs, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept = 0;
    virtual int32_t WINRT_CALL UndistortPoint(Windows::Foundation::Point input, Windows::Foundation::Point* result) noexcept = 0;
    virtual int32_t WINRT_CALL UndistortPoints(uint32_t __inputsSize, Windows::Foundation::Point* inputs, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::ICameraIntrinsicsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Foundation::Numerics::float2 focalLength, Windows::Foundation::Numerics::float2 principalPoint, Windows::Foundation::Numerics::float3 radialDistortion, Windows::Foundation::Numerics::float2 tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL UnprojectPoint(Windows::Foundation::Point sourcePoint, void* targetCoordinateSystem, Windows::Foundation::Numerics::float3* result) noexcept = 0;
    virtual int32_t WINRT_CALL UnprojectPoints(uint32_t __sourcePointsSize, Windows::Foundation::Point* sourcePoints, void* targetCoordinateSystem, uint32_t __resultsSize, Windows::Foundation::Numerics::float3* results) noexcept = 0;
    virtual int32_t WINRT_CALL MapPoint(Windows::Foundation::Point sourcePoint, void* targetCoordinateSystem, void* targetCameraIntrinsics, Windows::Foundation::Point* result) noexcept = 0;
    virtual int32_t WINRT_CALL MapPoints(uint32_t __sourcePointsSize, Windows::Foundation::Point* sourcePoints, void* targetCoordinateSystem, void* targetCameraIntrinsics, uint32_t __resultsSize, Windows::Foundation::Point* results) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameControlCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Exposure(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExposureCompensation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsoSpeed(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Focus(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotoConfirmationSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameControlCapabilities2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Flash(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExposureControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExposureCompensationControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsoSpeedControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FocusControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotoConfirmationEnabled(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PhotoConfirmationEnabled(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameController2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FlashControl(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameExposureCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Min(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Max(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Step(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Min(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Max(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Step(float* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameExposureCompensationControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameExposureControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Auto(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Auto(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameFlashCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedEyeReductionSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerSupported(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameFlashControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Mode(Windows::Media::Devices::Core::FrameFlashMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mode(Windows::Media::Devices::Core::FrameFlashMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Auto(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Auto(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedEyeReduction(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RedEyeReduction(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerPercent(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PowerPercent(float value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameFocusCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Min(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Max(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Step(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameFocusControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Min(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Max(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Step(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IFrameIsoSpeedControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Auto(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Auto(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Devices::Core::IVariablePhotoSequenceController>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Supported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxPhotosPerSecond(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosPerSecondLimit(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PhotosPerSecondLimit(float value) noexcept = 0;
    virtual int32_t WINRT_CALL GetHighestConcurrentFrameRate(void* captureProperties, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentFrameRate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrameCapabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredFrameControllers(void** items) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Devices_Core_ICameraIntrinsics
{
    Windows::Foundation::Numerics::float2 FocalLength() const;
    Windows::Foundation::Numerics::float2 PrincipalPoint() const;
    Windows::Foundation::Numerics::float3 RadialDistortion() const;
    Windows::Foundation::Numerics::float2 TangentialDistortion() const;
    uint32_t ImageWidth() const;
    uint32_t ImageHeight() const;
    Windows::Foundation::Point ProjectOntoFrame(Windows::Foundation::Numerics::float3 const& coordinate) const;
    Windows::Foundation::Numerics::float2 UnprojectAtUnitDepth(Windows::Foundation::Point const& pixelCoordinate) const;
    void ProjectManyOntoFrame(array_view<Windows::Foundation::Numerics::float3 const> coordinates, array_view<Windows::Foundation::Point> results) const;
    void UnprojectPixelsAtUnitDepth(array_view<Windows::Foundation::Point const> pixelCoordinates, array_view<Windows::Foundation::Numerics::float2> results) const;
};
template <> struct consume<Windows::Media::Devices::Core::ICameraIntrinsics> { template <typename D> using type = consume_Windows_Media_Devices_Core_ICameraIntrinsics<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_ICameraIntrinsics2
{
    Windows::Foundation::Numerics::float4x4 UndistortedProjectionTransform() const;
    Windows::Foundation::Point DistortPoint(Windows::Foundation::Point const& input) const;
    void DistortPoints(array_view<Windows::Foundation::Point const> inputs, array_view<Windows::Foundation::Point> results) const;
    Windows::Foundation::Point UndistortPoint(Windows::Foundation::Point const& input) const;
    void UndistortPoints(array_view<Windows::Foundation::Point const> inputs, array_view<Windows::Foundation::Point> results) const;
};
template <> struct consume<Windows::Media::Devices::Core::ICameraIntrinsics2> { template <typename D> using type = consume_Windows_Media_Devices_Core_ICameraIntrinsics2<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_ICameraIntrinsicsFactory
{
    Windows::Media::Devices::Core::CameraIntrinsics Create(Windows::Foundation::Numerics::float2 const& focalLength, Windows::Foundation::Numerics::float2 const& principalPoint, Windows::Foundation::Numerics::float3 const& radialDistortion, Windows::Foundation::Numerics::float2 const& tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight) const;
};
template <> struct consume<Windows::Media::Devices::Core::ICameraIntrinsicsFactory> { template <typename D> using type = consume_Windows_Media_Devices_Core_ICameraIntrinsicsFactory<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper
{
    Windows::Foundation::Numerics::float3 UnprojectPoint(Windows::Foundation::Point const& sourcePoint, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem) const;
    void UnprojectPoints(array_view<Windows::Foundation::Point const> sourcePoints, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, array_view<Windows::Foundation::Numerics::float3> results) const;
    Windows::Foundation::Point MapPoint(Windows::Foundation::Point const& sourcePoint, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, Windows::Media::Devices::Core::CameraIntrinsics const& targetCameraIntrinsics) const;
    void MapPoints(array_view<Windows::Foundation::Point const> sourcePoints, Windows::Perception::Spatial::SpatialCoordinateSystem const& targetCoordinateSystem, Windows::Media::Devices::Core::CameraIntrinsics const& targetCameraIntrinsics, array_view<Windows::Foundation::Point> results) const;
};
template <> struct consume<Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper> { template <typename D> using type = consume_Windows_Media_Devices_Core_IDepthCorrelatedCoordinateMapper<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameControlCapabilities
{
    Windows::Media::Devices::Core::FrameExposureCapabilities Exposure() const;
    Windows::Media::Devices::Core::FrameExposureCompensationCapabilities ExposureCompensation() const;
    Windows::Media::Devices::Core::FrameIsoSpeedCapabilities IsoSpeed() const;
    Windows::Media::Devices::Core::FrameFocusCapabilities Focus() const;
    bool PhotoConfirmationSupported() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameControlCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameControlCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameControlCapabilities2
{
    Windows::Media::Devices::Core::FrameFlashCapabilities Flash() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameControlCapabilities2> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameControlCapabilities2<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameController
{
    Windows::Media::Devices::Core::FrameExposureControl ExposureControl() const;
    Windows::Media::Devices::Core::FrameExposureCompensationControl ExposureCompensationControl() const;
    Windows::Media::Devices::Core::FrameIsoSpeedControl IsoSpeedControl() const;
    Windows::Media::Devices::Core::FrameFocusControl FocusControl() const;
    Windows::Foundation::IReference<bool> PhotoConfirmationEnabled() const;
    void PhotoConfirmationEnabled(optional<bool> const& value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameController> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameController<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameController2
{
    Windows::Media::Devices::Core::FrameFlashControl FlashControl() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameController2> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameController2<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameExposureCapabilities
{
    bool Supported() const;
    Windows::Foundation::TimeSpan Min() const;
    Windows::Foundation::TimeSpan Max() const;
    Windows::Foundation::TimeSpan Step() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameExposureCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameExposureCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities
{
    bool Supported() const;
    float Min() const;
    float Max() const;
    float Step() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameExposureCompensationCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameExposureCompensationControl
{
    Windows::Foundation::IReference<float> Value() const;
    void Value(optional<float> const& value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameExposureCompensationControl> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameExposureCompensationControl<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameExposureControl
{
    bool Auto() const;
    void Auto(bool value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Value() const;
    void Value(optional<Windows::Foundation::TimeSpan> const& value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameExposureControl> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameExposureControl<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameFlashCapabilities
{
    bool Supported() const;
    bool RedEyeReductionSupported() const;
    bool PowerSupported() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameFlashCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameFlashCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameFlashControl
{
    Windows::Media::Devices::Core::FrameFlashMode Mode() const;
    void Mode(Windows::Media::Devices::Core::FrameFlashMode const& value) const;
    bool Auto() const;
    void Auto(bool value) const;
    bool RedEyeReduction() const;
    void RedEyeReduction(bool value) const;
    float PowerPercent() const;
    void PowerPercent(float value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameFlashControl> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameFlashControl<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameFocusCapabilities
{
    bool Supported() const;
    uint32_t Min() const;
    uint32_t Max() const;
    uint32_t Step() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameFocusCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameFocusCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameFocusControl
{
    Windows::Foundation::IReference<uint32_t> Value() const;
    void Value(optional<uint32_t> const& value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameFocusControl> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameFocusControl<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities
{
    bool Supported() const;
    uint32_t Min() const;
    uint32_t Max() const;
    uint32_t Step() const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameIsoSpeedCapabilities<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl
{
    bool Auto() const;
    void Auto(bool value) const;
    Windows::Foundation::IReference<uint32_t> Value() const;
    void Value(optional<uint32_t> const& value) const;
};
template <> struct consume<Windows::Media::Devices::Core::IFrameIsoSpeedControl> { template <typename D> using type = consume_Windows_Media_Devices_Core_IFrameIsoSpeedControl<D>; };

template <typename D>
struct consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController
{
    bool Supported() const;
    float MaxPhotosPerSecond() const;
    float PhotosPerSecondLimit() const;
    void PhotosPerSecondLimit(float value) const;
    Windows::Media::MediaProperties::MediaRatio GetHighestConcurrentFrameRate(Windows::Media::MediaProperties::IMediaEncodingProperties const& captureProperties) const;
    Windows::Media::MediaProperties::MediaRatio GetCurrentFrameRate() const;
    Windows::Media::Devices::Core::FrameControlCapabilities FrameCapabilities() const;
    Windows::Foundation::Collections::IVector<Windows::Media::Devices::Core::FrameController> DesiredFrameControllers() const;
};
template <> struct consume<Windows::Media::Devices::Core::IVariablePhotoSequenceController> { template <typename D> using type = consume_Windows_Media_Devices_Core_IVariablePhotoSequenceController<D>; };

}
