// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct SpatialCoordinateSystem;
struct SpatialLocator;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview {

struct ISpatialGraphInteropFrameOfReferencePreview;
struct ISpatialGraphInteropPreviewStatics;
struct ISpatialGraphInteropPreviewStatics2;
struct SpatialGraphInteropFrameOfReferencePreview;
struct SpatialGraphInteropPreview;

}

namespace winrt::impl {

template <> struct category<Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview>{ using type = class_category; };
template <> struct name<Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropFrameOfReferencePreview" }; };
template <> struct name<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics" }; };
template <> struct name<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Preview.ISpatialGraphInteropPreviewStatics2" }; };
template <> struct name<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Preview.SpatialGraphInteropFrameOfReferencePreview" }; };
template <> struct name<Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Preview.SpatialGraphInteropPreview" }; };
template <> struct guid_storage<Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ static constexpr guid value{ 0xA8271B23,0x735F,0x5729,{ 0xA9,0x8E,0xE6,0x4E,0xD1,0x89,0xAB,0xC5 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ static constexpr guid value{ 0xC042644C,0x20D8,0x4ED0,{ 0xAE,0xF7,0x68,0x05,0xB8,0xE5,0x3F,0x55 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ static constexpr guid value{ 0x2490B15F,0x6CBD,0x4B1E,{ 0xB7,0x65,0x31,0xE4,0x62,0xA3,0x2D,0xF2 } }; };
template <> struct default_interface<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>{ using type = Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview; };

template <> struct abi<Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NodeId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CoordinateSystemToNodeTransform(Windows::Foundation::Numerics::float4x4* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateCoordinateSystemForNode(winrt::guid nodeId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCoordinateSystemForNodeWithPosition(winrt::guid nodeId, Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCoordinateSystemForNodeWithPositionAndOrientation(winrt::guid nodeId, Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL CreateLocatorForNode(winrt::guid nodeId, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryCreateFrameOfReference(void* coordinateSystem, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateFrameOfReferenceWithPosition(void* coordinateSystem, Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateFrameOfReferenceWithPositionAndOrientation(void* coordinateSystem, Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
    winrt::guid NodeId() const;
    Windows::Foundation::Numerics::float4x4 CoordinateSystemToNodeTransform() const;
};
template <> struct consume<Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> { template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId) const;
    Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition) const;
    Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
    Windows::Perception::Spatial::SpatialLocator CreateLocatorForNode(winrt::guid const& nodeId) const;
};
template <> struct consume<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2
{
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition) const;
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
};
template <> struct consume<Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> { template <typename D> using type = consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>; };

}
