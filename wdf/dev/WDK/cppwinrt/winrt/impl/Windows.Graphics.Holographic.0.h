// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX {

enum class DirectXPixelFormat;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct IDirect3DDevice;
struct IDirect3DSurface;

}

WINRT_EXPORT namespace winrt::Windows::Perception {

struct PerceptionTimestamp;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct SpatialBoundingFrustum;
struct SpatialCoordinateSystem;
struct SpatialLocator;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

struct CoreWindow;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Holographic {

enum class HolographicFramePresentResult : int32_t
{
    Success = 0,
    DeviceRemoved = 1,
};

enum class HolographicFramePresentWaitBehavior : int32_t
{
    WaitForFrameToFinish = 0,
    DoNotWaitForFrameToFinish = 1,
};

enum class HolographicReprojectionMode : int32_t
{
    PositionAndOrientation = 0,
    OrientationOnly = 1,
    Disabled = 2,
};

enum class HolographicSpaceUserPresence : int32_t
{
    Absent = 0,
    PresentPassive = 1,
    PresentActive = 2,
};

enum class HolographicViewConfigurationKind : int32_t
{
    Display = 0,
    PhotoVideoCamera = 1,
};

struct IHolographicCamera;
struct IHolographicCamera2;
struct IHolographicCamera3;
struct IHolographicCamera4;
struct IHolographicCamera5;
struct IHolographicCamera6;
struct IHolographicCameraPose;
struct IHolographicCameraPose2;
struct IHolographicCameraRenderingParameters;
struct IHolographicCameraRenderingParameters2;
struct IHolographicCameraRenderingParameters3;
struct IHolographicCameraViewportParameters;
struct IHolographicDisplay;
struct IHolographicDisplay2;
struct IHolographicDisplay3;
struct IHolographicDisplayStatics;
struct IHolographicFrame;
struct IHolographicFrame2;
struct IHolographicFramePrediction;
struct IHolographicFramePresentationMonitor;
struct IHolographicFramePresentationReport;
struct IHolographicQuadLayer;
struct IHolographicQuadLayerFactory;
struct IHolographicQuadLayerUpdateParameters;
struct IHolographicQuadLayerUpdateParameters2;
struct IHolographicSpace;
struct IHolographicSpace2;
struct IHolographicSpaceCameraAddedEventArgs;
struct IHolographicSpaceCameraRemovedEventArgs;
struct IHolographicSpaceStatics;
struct IHolographicSpaceStatics2;
struct IHolographicSpaceStatics3;
struct IHolographicViewConfiguration;
struct HolographicCamera;
struct HolographicCameraPose;
struct HolographicCameraRenderingParameters;
struct HolographicCameraViewportParameters;
struct HolographicDisplay;
struct HolographicFrame;
struct HolographicFramePrediction;
struct HolographicFramePresentationMonitor;
struct HolographicFramePresentationReport;
struct HolographicQuadLayer;
struct HolographicQuadLayerUpdateParameters;
struct HolographicSpace;
struct HolographicSpaceCameraAddedEventArgs;
struct HolographicSpaceCameraRemovedEventArgs;
struct HolographicViewConfiguration;
struct HolographicAdapterId;
struct HolographicStereoTransform;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::Holographic::IHolographicCamera>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCamera2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCamera3>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCamera4>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCamera5>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCamera6>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraPose>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraPose2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicCameraViewportParameters>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicDisplay>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicDisplay2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicDisplay3>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicDisplayStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicFrame>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicFrame2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicFramePrediction>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicFramePresentationMonitor>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicFramePresentationReport>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicQuadLayer>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicQuadLayerFactory>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpace>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpace2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpaceStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpaceStatics2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicSpaceStatics3>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::IHolographicViewConfiguration>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicCamera>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicCameraPose>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicCameraRenderingParameters>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicCameraViewportParameters>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicDisplay>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFrame>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFramePrediction>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFramePresentationMonitor>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFramePresentationReport>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicQuadLayer>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicSpace>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicViewConfiguration>{ using type = class_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFramePresentResult>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicReprojectionMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicSpaceUserPresence>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicViewConfigurationKind>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Holographic::HolographicAdapterId>{ using type = struct_category<uint32_t,int32_t>; };
template <> struct category<Windows::Graphics::Holographic::HolographicStereoTransform>{ using type = struct_category<Windows::Foundation::Numerics::float4x4,Windows::Foundation::Numerics::float4x4>; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera3>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera3" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera4>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera4" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera5>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera5" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCamera6>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCamera6" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraPose>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraPose" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraPose2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraPose2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraRenderingParameters" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraRenderingParameters2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraRenderingParameters3" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicCameraViewportParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicCameraViewportParameters" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicDisplay>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicDisplay" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicDisplay2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicDisplay2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicDisplay3>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicDisplay3" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicDisplayStatics>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicDisplayStatics" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicFrame>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicFrame" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicFrame2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicFrame2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicFramePrediction>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicFramePrediction" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicFramePresentationMonitor>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicFramePresentationMonitor" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicFramePresentationReport>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicFramePresentationReport" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicQuadLayer>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicQuadLayer" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicQuadLayerFactory>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicQuadLayerFactory" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicQuadLayerUpdateParameters" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicQuadLayerUpdateParameters2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpace>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpace" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpace2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpace2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpaceCameraAddedEventArgs" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpaceCameraRemovedEventArgs" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpaceStatics>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpaceStatics" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpaceStatics2>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpaceStatics2" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicSpaceStatics3>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicSpaceStatics3" }; };
template <> struct name<Windows::Graphics::Holographic::IHolographicViewConfiguration>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.IHolographicViewConfiguration" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicCamera>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicCamera" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicCameraPose>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicCameraPose" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicCameraRenderingParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicCameraRenderingParameters" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicCameraViewportParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicCameraViewportParameters" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicDisplay>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicDisplay" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFrame>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFrame" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFramePrediction>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFramePrediction" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFramePresentationMonitor>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFramePresentationMonitor" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFramePresentationReport>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFramePresentationReport" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicQuadLayer>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicQuadLayer" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicQuadLayerUpdateParameters" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicSpace>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicSpace" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicSpaceCameraAddedEventArgs" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicSpaceCameraRemovedEventArgs" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicViewConfiguration>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicViewConfiguration" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFramePresentResult>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFramePresentResult" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicFramePresentWaitBehavior" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicReprojectionMode>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicReprojectionMode" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicSpaceUserPresence>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicSpaceUserPresence" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicViewConfigurationKind>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicViewConfigurationKind" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicAdapterId>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicAdapterId" }; };
template <> struct name<Windows::Graphics::Holographic::HolographicStereoTransform>{ static constexpr auto & value{ L"Windows.Graphics.Holographic.HolographicStereoTransform" }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera>{ static constexpr guid value{ 0xE4E98445,0x9BED,0x4980,{ 0x9B,0xA0,0xE8,0x76,0x80,0xD1,0xCB,0x74 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera2>{ static constexpr guid value{ 0xB55B9F1A,0xBA8C,0x4F84,{ 0xAD,0x79,0x2E,0x7E,0x1E,0x24,0x50,0xF3 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera3>{ static constexpr guid value{ 0x45AA4FB3,0x7B59,0x524E,{ 0x4A,0x3F,0x4A,0x6A,0xD6,0x65,0x04,0x77 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera4>{ static constexpr guid value{ 0x9A2531D6,0x4723,0x4F39,{ 0xA9,0xA5,0x9D,0x05,0x18,0x1D,0x9B,0x44 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera5>{ static constexpr guid value{ 0x229706F2,0x628D,0x4EF5,{ 0x9C,0x08,0xA6,0x3F,0xDD,0x77,0x87,0xC6 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCamera6>{ static constexpr guid value{ 0x0209194F,0x632D,0x5154,{ 0xAB,0x52,0x0B,0x5D,0x15,0xB1,0x25,0x05 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraPose>{ static constexpr guid value{ 0x0D7D7E30,0x12DE,0x45BD,{ 0x91,0x2B,0xC7,0xF6,0x56,0x15,0x99,0xD1 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraPose2>{ static constexpr guid value{ 0x232BE073,0x5D2D,0x4560,{ 0x81,0x4E,0x26,0x97,0xC4,0xFC,0xE1,0x6B } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>{ static constexpr guid value{ 0x8EAC2ED1,0x5BF4,0x4E16,{ 0x82,0x36,0xAE,0x08,0x00,0xC1,0x1D,0x0D } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>{ static constexpr guid value{ 0x261270E3,0xB696,0x4634,{ 0x94,0xD6,0xBE,0x06,0x81,0x64,0x35,0x99 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3>{ static constexpr guid value{ 0xB1AA513F,0x136D,0x4B06,{ 0xB9,0xD4,0xE4,0xB9,0x14,0xCD,0x06,0x83 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicCameraViewportParameters>{ static constexpr guid value{ 0x80CDF3F7,0x842A,0x41E1,{ 0x93,0xED,0x56,0x92,0xAB,0x1F,0xBB,0x10 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicDisplay>{ static constexpr guid value{ 0x9ACEA414,0x1D9F,0x4090,{ 0xA3,0x88,0x90,0xC0,0x6F,0x6E,0xAE,0x9C } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicDisplay2>{ static constexpr guid value{ 0x75AC3F82,0xE755,0x436C,{ 0x8D,0x96,0x4D,0x32,0xD1,0x31,0x47,0x3E } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicDisplay3>{ static constexpr guid value{ 0xFC4C6AC6,0x6480,0x5008,{ 0xB2,0x9E,0x15,0x7D,0x77,0xC8,0x43,0xF7 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicDisplayStatics>{ static constexpr guid value{ 0xCB374983,0xE7B0,0x4841,{ 0x83,0x55,0x3A,0xE5,0xB5,0x36,0xE9,0xA4 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicFrame>{ static constexpr guid value{ 0xC6988EB6,0xA8B9,0x3054,{ 0xA6,0xEB,0xD6,0x24,0xB6,0x53,0x63,0x75 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicFrame2>{ static constexpr guid value{ 0x283F37BF,0x3BF2,0x5E91,{ 0x66,0x33,0x87,0x05,0x74,0xE6,0xF2,0x17 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicFramePrediction>{ static constexpr guid value{ 0x520F4DE1,0x5C0A,0x4E79,{ 0xA8,0x1E,0x6A,0xBE,0x02,0xBB,0x27,0x39 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicFramePresentationMonitor>{ static constexpr guid value{ 0xCA87256C,0x6FAE,0x428E,{ 0xBB,0x83,0x25,0xDF,0xEE,0x51,0x13,0x6B } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicFramePresentationReport>{ static constexpr guid value{ 0x80BAF614,0xF2F4,0x4C8A,{ 0x8D,0xE3,0x06,0x5C,0x78,0xF6,0xD5,0xDE } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicQuadLayer>{ static constexpr guid value{ 0x903460C9,0xC9D9,0x5D5C,{ 0x41,0xAC,0xA2,0xD5,0xAB,0x0F,0xD3,0x31 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicQuadLayerFactory>{ static constexpr guid value{ 0xA67538F3,0x5A14,0x5A10,{ 0x48,0x9A,0x45,0x50,0x65,0xB3,0x7B,0x76 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters>{ static constexpr guid value{ 0x2B0EA3B0,0x798D,0x5BCA,{ 0x55,0xC2,0x2C,0x0C,0x76,0x2E,0xBB,0x08 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2>{ static constexpr guid value{ 0x4F33D32D,0x82C1,0x46C1,{ 0x89,0x80,0x3C,0xB7,0x0D,0x98,0x18,0x2B } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpace>{ static constexpr guid value{ 0x4380DBA6,0x5E78,0x434F,{ 0x80,0x7C,0x34,0x33,0xD1,0xEF,0xE8,0xB7 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpace2>{ static constexpr guid value{ 0x4F81A9A8,0xB7FF,0x4883,{ 0x98,0x27,0x7D,0x67,0x72,0x87,0xEA,0x70 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs>{ static constexpr guid value{ 0x58F1DA35,0xBBB3,0x3C8F,{ 0x99,0x3D,0x6C,0x80,0xE7,0xFE,0xB9,0x9F } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs>{ static constexpr guid value{ 0x805444A8,0xF2AE,0x322E,{ 0x8D,0xA9,0x83,0x6A,0x0A,0x95,0xA4,0xC1 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpaceStatics>{ static constexpr guid value{ 0x364E6064,0xC8F2,0x3BA1,{ 0x83,0x91,0x66,0xB8,0x48,0x9E,0x67,0xFD } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpaceStatics2>{ static constexpr guid value{ 0x0E777088,0x75FC,0x48AF,{ 0x87,0x58,0x06,0x52,0xF6,0xF0,0x7C,0x59 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicSpaceStatics3>{ static constexpr guid value{ 0x3B00DE3D,0xB1A3,0x4DFE,{ 0x8E,0x79,0xFE,0xC5,0x90,0x9E,0x6D,0xF8 } }; };
template <> struct guid_storage<Windows::Graphics::Holographic::IHolographicViewConfiguration>{ static constexpr guid value{ 0x5C1DE6E6,0x67E9,0x5004,{ 0xB0,0x2C,0x67,0xA3,0xA1,0x22,0xB5,0x76 } }; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicCamera>{ using type = Windows::Graphics::Holographic::IHolographicCamera; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicCameraPose>{ using type = Windows::Graphics::Holographic::IHolographicCameraPose; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicCameraRenderingParameters>{ using type = Windows::Graphics::Holographic::IHolographicCameraRenderingParameters; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicCameraViewportParameters>{ using type = Windows::Graphics::Holographic::IHolographicCameraViewportParameters; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicDisplay>{ using type = Windows::Graphics::Holographic::IHolographicDisplay; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicFrame>{ using type = Windows::Graphics::Holographic::IHolographicFrame; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicFramePrediction>{ using type = Windows::Graphics::Holographic::IHolographicFramePrediction; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicFramePresentationMonitor>{ using type = Windows::Graphics::Holographic::IHolographicFramePresentationMonitor; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicFramePresentationReport>{ using type = Windows::Graphics::Holographic::IHolographicFramePresentationReport; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicQuadLayer>{ using type = Windows::Graphics::Holographic::IHolographicQuadLayer; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters>{ using type = Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicSpace>{ using type = Windows::Graphics::Holographic::IHolographicSpace; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs>{ using type = Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs>{ using type = Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs; };
template <> struct default_interface<Windows::Graphics::Holographic::HolographicViewConfiguration>{ using type = Windows::Graphics::Holographic::IHolographicViewConfiguration; };

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RenderTargetSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ViewportScaleFactor(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ViewportScaleFactor(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetNearPlaneDistance(double value) noexcept = 0;
    virtual int32_t WINRT_CALL SetFarPlaneDistance(double value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LeftViewportParameters(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_RightViewportParameters(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_Display(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPrimaryLayerEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsPrimaryLayerEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxQuadLayerCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_QuadLayers(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanOverrideViewport(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsHardwareContentProtectionSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsHardwareContentProtectionEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsHardwareContentProtectionEnabled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCamera6>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewConfiguration(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraPose>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HolographicCamera(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Viewport(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetViewTransform(void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProjectionTransform(struct struct_Windows_Graphics_Holographic_HolographicStereoTransform* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetCullingFrustum(void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetVisibleFrustum(void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NearPlaneDistance(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FarPlaneDistance(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraPose2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL OverrideViewTransform(void* coordinateSystem, struct struct_Windows_Graphics_Holographic_HolographicStereoTransform coordinateSystemToViewTransform) noexcept = 0;
    virtual int32_t WINRT_CALL OverrideProjectionTransform(struct struct_Windows_Graphics_Holographic_HolographicStereoTransform projectionTransform) noexcept = 0;
    virtual int32_t WINRT_CALL OverrideViewport(Windows::Foundation::Rect leftViewport, Windows::Foundation::Rect rightViewport) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetFocusPoint(void* coordinateSystem, Windows::Foundation::Numerics::float3 position) noexcept = 0;
    virtual int32_t WINRT_CALL SetFocusPointWithNormal(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::float3 normal) noexcept = 0;
    virtual int32_t WINRT_CALL SetFocusPointWithNormalLinearVelocity(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::float3 normal, Windows::Foundation::Numerics::float3 linearVelocity) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direct3D11Device(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direct3D11BackBuffer(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode value) noexcept = 0;
    virtual int32_t WINRT_CALL CommitDirect3D11DepthBuffer(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsContentProtectionEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsContentProtectionEnabled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicCameraViewportParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HiddenAreaMesh(uint32_t* __valueSize, Windows::Foundation::Numerics::float2** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VisibleAreaMesh(uint32_t* __valueSize, Windows::Foundation::Numerics::float2** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicDisplay>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxViewportSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsOpaque(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdapterId(struct struct_Windows_Graphics_Holographic_HolographicAdapterId* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpatialLocator(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicDisplay2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RefreshRate(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicDisplay3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetViewConfiguration(Windows::Graphics::Holographic::HolographicViewConfigurationKind kind, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicDisplayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicFrame>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AddedCameras(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemovedCameras(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetRenderingParameters(void* cameraPose, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrentPrediction(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateCurrentPrediction() noexcept = 0;
    virtual int32_t WINRT_CALL PresentUsingCurrentPrediction(Windows::Graphics::Holographic::HolographicFramePresentResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL PresentUsingCurrentPredictionWithBehavior(Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior waitBehavior, Windows::Graphics::Holographic::HolographicFramePresentResult* result) noexcept = 0;
    virtual int32_t WINRT_CALL WaitForFrameToFinish() noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicFrame2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetQuadLayerUpdateParameters(void* layer, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicFramePrediction>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CameraPoses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicFramePresentationMonitor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ReadReports(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicFramePresentationReport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CompositorGpuDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppGpuDuration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppGpuOverrun(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MissedPresentationOpportunityCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PresentationCount(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicQuadLayer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicQuadLayerFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Foundation::Size size, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithPixelFormat(Windows::Foundation::Size size, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AcquireBufferToUpdateContent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateViewport(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateContentProtectionEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateExtents(Windows::Foundation::Numerics::float2 value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateLocationWithStationaryMode(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateLocationWithDisplayRelativeMode(Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanAcquireWithHardwareProtection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL AcquireBufferToUpdateContentWithHardwareProtection(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpace>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PrimaryAdapterId(struct struct_Windows_Graphics_Holographic_HolographicAdapterId* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDirect3D11Device(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_CameraAdded(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CameraAdded(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_CameraRemoved(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CameraRemoved(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL CreateNextFrame(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpace2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserPresence(Windows::Graphics::Holographic::HolographicSpaceUserPresence* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_UserPresenceChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UserPresenceChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL WaitForNextFrameReady() noexcept = 0;
    virtual int32_t WINRT_CALL WaitForNextFrameReadyWithHeadStart(Windows::Foundation::TimeSpan requestedHeadStartDuration) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFramePresentationMonitor(uint32_t maxQueuedReports, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Camera(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Camera(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpaceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForCoreWindow(void* window, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpaceStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_IsAvailableChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsAvailableChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicSpaceStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsConfigured(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Holographic::IHolographicViewConfiguration>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NativeRenderTargetSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RenderTargetSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestRenderTargetSize(Windows::Foundation::Size size, Windows::Foundation::Size* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedPixelFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsStereo(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RefreshRate(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::Graphics::Holographic::HolographicViewConfigurationKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Display(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera
{
    Windows::Foundation::Size RenderTargetSize() const;
    double ViewportScaleFactor() const;
    void ViewportScaleFactor(double value) const;
    bool IsStereo() const;
    uint32_t Id() const;
    void SetNearPlaneDistance(double value) const;
    void SetFarPlaneDistance(double value) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera2
{
    Windows::Graphics::Holographic::HolographicCameraViewportParameters LeftViewportParameters() const;
    Windows::Graphics::Holographic::HolographicCameraViewportParameters RightViewportParameters() const;
    Windows::Graphics::Holographic::HolographicDisplay Display() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera3
{
    bool IsPrimaryLayerEnabled() const;
    void IsPrimaryLayerEnabled(bool value) const;
    uint32_t MaxQuadLayerCount() const;
    Windows::Foundation::Collections::IVector<Windows::Graphics::Holographic::HolographicQuadLayer> QuadLayers() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera3> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera3<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera4
{
    bool CanOverrideViewport() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera4> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera4<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera5
{
    bool IsHardwareContentProtectionSupported() const;
    bool IsHardwareContentProtectionEnabled() const;
    void IsHardwareContentProtectionEnabled(bool value) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera5> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera5<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCamera6
{
    Windows::Graphics::Holographic::HolographicViewConfiguration ViewConfiguration() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCamera6> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCamera6<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraPose
{
    Windows::Graphics::Holographic::HolographicCamera HolographicCamera() const;
    Windows::Foundation::Rect Viewport() const;
    Windows::Foundation::IReference<Windows::Graphics::Holographic::HolographicStereoTransform> TryGetViewTransform(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Graphics::Holographic::HolographicStereoTransform ProjectionTransform() const;
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> TryGetCullingFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> TryGetVisibleFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    double NearPlaneDistance() const;
    double FarPlaneDistance() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraPose> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraPose2
{
    void OverrideViewTransform(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Graphics::Holographic::HolographicStereoTransform const& coordinateSystemToViewTransform) const;
    void OverrideProjectionTransform(Windows::Graphics::Holographic::HolographicStereoTransform const& projectionTransform) const;
    void OverrideViewport(Windows::Foundation::Rect const& leftViewport, Windows::Foundation::Rect const& rightViewport) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraPose2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraPose2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters
{
    void SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position) const;
    void SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::float3 const& normal) const;
    void SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::float3 const& normal, Windows::Foundation::Numerics::float3 const& linearVelocity) const;
    Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice Direct3D11Device() const;
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface Direct3D11BackBuffer() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters2
{
    Windows::Graphics::Holographic::HolographicReprojectionMode ReprojectionMode() const;
    void ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode const& value) const;
    void CommitDirect3D11DepthBuffer(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& value) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters3
{
    bool IsContentProtectionEnabled() const;
    void IsContentProtectionEnabled(bool value) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters3<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicCameraViewportParameters
{
    com_array<Windows::Foundation::Numerics::float2> HiddenAreaMesh() const;
    com_array<Windows::Foundation::Numerics::float2> VisibleAreaMesh() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicCameraViewportParameters> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicCameraViewportParameters<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicDisplay
{
    hstring DisplayName() const;
    Windows::Foundation::Size MaxViewportSize() const;
    bool IsStereo() const;
    bool IsOpaque() const;
    Windows::Graphics::Holographic::HolographicAdapterId AdapterId() const;
    Windows::Perception::Spatial::SpatialLocator SpatialLocator() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicDisplay> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicDisplay<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicDisplay2
{
    double RefreshRate() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicDisplay2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicDisplay2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicDisplay3
{
    Windows::Graphics::Holographic::HolographicViewConfiguration TryGetViewConfiguration(Windows::Graphics::Holographic::HolographicViewConfigurationKind const& kind) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicDisplay3> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicDisplay3<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicDisplayStatics
{
    Windows::Graphics::Holographic::HolographicDisplay GetDefault() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicDisplayStatics> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicDisplayStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicFrame
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> AddedCameras() const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> RemovedCameras() const;
    Windows::Graphics::Holographic::HolographicCameraRenderingParameters GetRenderingParameters(Windows::Graphics::Holographic::HolographicCameraPose const& cameraPose) const;
    Windows::Foundation::TimeSpan Duration() const;
    Windows::Graphics::Holographic::HolographicFramePrediction CurrentPrediction() const;
    void UpdateCurrentPrediction() const;
    Windows::Graphics::Holographic::HolographicFramePresentResult PresentUsingCurrentPrediction() const;
    Windows::Graphics::Holographic::HolographicFramePresentResult PresentUsingCurrentPrediction(Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior const& waitBehavior) const;
    void WaitForFrameToFinish() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicFrame> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicFrame<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicFrame2
{
    Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters GetQuadLayerUpdateParameters(Windows::Graphics::Holographic::HolographicQuadLayer const& layer) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicFrame2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicFrame2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicFramePrediction
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCameraPose> CameraPoses() const;
    Windows::Perception::PerceptionTimestamp Timestamp() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicFramePrediction> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicFramePrediction<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicFramePresentationMonitor
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicFramePresentationReport> ReadReports() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicFramePresentationMonitor> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicFramePresentationMonitor<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport
{
    Windows::Foundation::TimeSpan CompositorGpuDuration() const;
    Windows::Foundation::TimeSpan AppGpuDuration() const;
    Windows::Foundation::TimeSpan AppGpuOverrun() const;
    uint32_t MissedPresentationOpportunityCount() const;
    uint32_t PresentationCount() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicFramePresentationReport> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicQuadLayer
{
    Windows::Graphics::DirectX::DirectXPixelFormat PixelFormat() const;
    Windows::Foundation::Size Size() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicQuadLayer> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicQuadLayer<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicQuadLayerFactory
{
    Windows::Graphics::Holographic::HolographicQuadLayer Create(Windows::Foundation::Size const& size) const;
    Windows::Graphics::Holographic::HolographicQuadLayer CreateWithPixelFormat(Windows::Foundation::Size const& size, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicQuadLayerFactory> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicQuadLayerFactory<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface AcquireBufferToUpdateContent() const;
    void UpdateViewport(Windows::Foundation::Rect const& value) const;
    void UpdateContentProtectionEnabled(bool value) const;
    void UpdateExtents(Windows::Foundation::Numerics::float2 const& value) const;
    void UpdateLocationWithStationaryMode(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const;
    void UpdateLocationWithDisplayRelativeMode(Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters2
{
    bool CanAcquireWithHardwareProtection() const;
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface AcquireBufferToUpdateContentWithHardwareProtection() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpace
{
    Windows::Graphics::Holographic::HolographicAdapterId PrimaryAdapterId() const;
    void SetDirect3D11Device(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& value) const;
    winrt::event_token CameraAdded(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const& handler) const;
    using CameraAdded_revoker = impl::event_revoker<Windows::Graphics::Holographic::IHolographicSpace, &impl::abi_t<Windows::Graphics::Holographic::IHolographicSpace>::remove_CameraAdded>;
    CameraAdded_revoker CameraAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const& handler) const;
    void CameraAdded(winrt::event_token const& cookie) const noexcept;
    winrt::event_token CameraRemoved(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const& handler) const;
    using CameraRemoved_revoker = impl::event_revoker<Windows::Graphics::Holographic::IHolographicSpace, &impl::abi_t<Windows::Graphics::Holographic::IHolographicSpace>::remove_CameraRemoved>;
    CameraRemoved_revoker CameraRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const& handler) const;
    void CameraRemoved(winrt::event_token const& cookie) const noexcept;
    Windows::Graphics::Holographic::HolographicFrame CreateNextFrame() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpace> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpace<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpace2
{
    Windows::Graphics::Holographic::HolographicSpaceUserPresence UserPresence() const;
    winrt::event_token UserPresenceChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const& handler) const;
    using UserPresenceChanged_revoker = impl::event_revoker<Windows::Graphics::Holographic::IHolographicSpace2, &impl::abi_t<Windows::Graphics::Holographic::IHolographicSpace2>::remove_UserPresenceChanged>;
    UserPresenceChanged_revoker UserPresenceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const& handler) const;
    void UserPresenceChanged(winrt::event_token const& token) const noexcept;
    void WaitForNextFrameReady() const;
    void WaitForNextFrameReadyWithHeadStart(Windows::Foundation::TimeSpan const& requestedHeadStartDuration) const;
    Windows::Graphics::Holographic::HolographicFramePresentationMonitor CreateFramePresentationMonitor(uint32_t maxQueuedReports) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpace2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpace2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpaceCameraAddedEventArgs
{
    Windows::Graphics::Holographic::HolographicCamera Camera() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpaceCameraAddedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpaceCameraRemovedEventArgs
{
    Windows::Graphics::Holographic::HolographicCamera Camera() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpaceCameraRemovedEventArgs<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpaceStatics
{
    Windows::Graphics::Holographic::HolographicSpace CreateForCoreWindow(Windows::UI::Core::CoreWindow const& window) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpaceStatics> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpaceStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2
{
    bool IsSupported() const;
    bool IsAvailable() const;
    winrt::event_token IsAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using IsAvailableChanged_revoker = impl::event_revoker<Windows::Graphics::Holographic::IHolographicSpaceStatics2, &impl::abi_t<Windows::Graphics::Holographic::IHolographicSpaceStatics2>::remove_IsAvailableChanged>;
    IsAvailableChanged_revoker IsAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void IsAvailableChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpaceStatics2> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicSpaceStatics3
{
    bool IsConfigured() const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicSpaceStatics3> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicSpaceStatics3<D>; };

template <typename D>
struct consume_Windows_Graphics_Holographic_IHolographicViewConfiguration
{
    Windows::Foundation::Size NativeRenderTargetSize() const;
    Windows::Foundation::Size RenderTargetSize() const;
    Windows::Foundation::Size RequestRenderTargetSize(Windows::Foundation::Size const& size) const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> SupportedPixelFormats() const;
    Windows::Graphics::DirectX::DirectXPixelFormat PixelFormat() const;
    void PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const;
    bool IsStereo() const;
    double RefreshRate() const;
    Windows::Graphics::Holographic::HolographicViewConfigurationKind Kind() const;
    Windows::Graphics::Holographic::HolographicDisplay Display() const;
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
};
template <> struct consume<Windows::Graphics::Holographic::IHolographicViewConfiguration> { template <typename D> using type = consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>; };

struct struct_Windows_Graphics_Holographic_HolographicAdapterId
{
    uint32_t LowPart;
    int32_t HighPart;
};
template <> struct abi<Windows::Graphics::Holographic::HolographicAdapterId>{ using type = struct_Windows_Graphics_Holographic_HolographicAdapterId; };


struct struct_Windows_Graphics_Holographic_HolographicStereoTransform
{
    Windows::Foundation::Numerics::float4x4 Left;
    Windows::Foundation::Numerics::float4x4 Right;
};
template <> struct abi<Windows::Graphics::Holographic::HolographicStereoTransform>{ using type = struct_Windows_Graphics_Holographic_HolographicStereoTransform; };


}
