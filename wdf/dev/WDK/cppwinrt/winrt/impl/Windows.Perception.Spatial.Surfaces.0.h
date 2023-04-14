// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX {

enum class DirectXPixelFormat;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

enum class SpatialPerceptionAccessStatus;
struct SpatialBoundingOrientedBox;
struct SpatialBoundingVolume;
struct SpatialCoordinateSystem;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Surfaces {

struct ISpatialSurfaceInfo;
struct ISpatialSurfaceMesh;
struct ISpatialSurfaceMeshBuffer;
struct ISpatialSurfaceMeshOptions;
struct ISpatialSurfaceMeshOptionsStatics;
struct ISpatialSurfaceObserver;
struct ISpatialSurfaceObserverStatics;
struct ISpatialSurfaceObserverStatics2;
struct SpatialSurfaceInfo;
struct SpatialSurfaceMesh;
struct SpatialSurfaceMeshBuffer;
struct SpatialSurfaceMeshOptions;
struct SpatialSurfaceObserver;

}

namespace winrt::impl {

template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptionsStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics2>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::SpatialSurfaceInfo>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMesh>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshOptions>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::Surfaces::SpatialSurfaceObserver>{ using type = class_category; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceInfo" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceMesh" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceMeshBuffer" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceMeshOptions" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptionsStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceMeshOptionsStatics" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceObserver" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceObserverStatics" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics2>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.ISpatialSurfaceObserverStatics2" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::SpatialSurfaceInfo>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.SpatialSurfaceInfo" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMesh>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.SpatialSurfaceMesh" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.SpatialSurfaceMeshBuffer" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshOptions>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.SpatialSurfaceMeshOptions" }; };
template <> struct name<Windows::Perception::Spatial::Surfaces::SpatialSurfaceObserver>{ static constexpr auto & value{ L"Windows.Perception.Spatial.Surfaces.SpatialSurfaceObserver" }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo>{ static constexpr guid value{ 0xF8E9EBE7,0x39B7,0x3962,{ 0xBB,0x03,0x57,0xF5,0x6E,0x1F,0xB0,0xA1 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh>{ static constexpr guid value{ 0x108F57D9,0xDF0D,0x3950,{ 0xA0,0xFD,0xF9,0x72,0xC7,0x7C,0x27,0xB4 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer>{ static constexpr guid value{ 0x93CF59E0,0x871F,0x33F8,{ 0x98,0xB2,0x03,0xD1,0x01,0x45,0x8F,0x6F } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions>{ static constexpr guid value{ 0xD2759F89,0x3572,0x3D2D,{ 0xA1,0x0D,0x5F,0xEE,0x93,0x94,0xAA,0x37 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptionsStatics>{ static constexpr guid value{ 0x9B340ABF,0x9781,0x4505,{ 0x89,0x35,0x01,0x35,0x75,0xCA,0xAE,0x5E } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver>{ static constexpr guid value{ 0x10B69819,0xDDCA,0x3483,{ 0xAC,0x3A,0x74,0x8F,0xE8,0xC8,0x6D,0xF5 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics>{ static constexpr guid value{ 0x165951ED,0x2108,0x4168,{ 0x91,0x75,0x87,0xE0,0x27,0xBC,0x92,0x85 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics2>{ static constexpr guid value{ 0x0F534261,0xC55D,0x4E6B,{ 0xA8,0x95,0xA1,0x9D,0xE6,0x9A,0x42,0xE3 } }; };
template <> struct default_interface<Windows::Perception::Spatial::Surfaces::SpatialSurfaceInfo>{ using type = Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo; };
template <> struct default_interface<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMesh>{ using type = Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh; };
template <> struct default_interface<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer>{ using type = Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer; };
template <> struct default_interface<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshOptions>{ using type = Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions; };
template <> struct default_interface<Windows::Perception::Spatial::Surfaces::SpatialSurfaceObserver>{ using type = Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver; };

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateTime(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetBounds(void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryComputeLatestMeshAsync(double maxTrianglesPerCubicMeter, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryComputeLatestMeshWithOptionsAsync(double maxTrianglesPerCubicMeter, void* options, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SurfaceInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TriangleIndices(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VertexPositions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VertexPositionScale(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VertexNormals(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Format(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Stride(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Data(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_VertexPositionFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_VertexPositionFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TriangleIndexFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TriangleIndexFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VertexNormalFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_VertexNormalFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IncludeVertexNormals(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IncludeVertexNormals(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptionsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SupportedVertexPositionFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedTriangleIndexFormats(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedVertexNormalFormats(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetObservedSurfaces(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetBoundingVolume(void* bounds) noexcept = 0;
    virtual int32_t WINRT_CALL SetBoundingVolumes(void* bounds) noexcept = 0;
    virtual int32_t WINRT_CALL add_ObservedSurfacesChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ObservedSurfacesChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(bool* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceInfo
{
    winrt::guid Id() const;
    Windows::Foundation::DateTime UpdateTime() const;
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingOrientedBox> TryGetBounds(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMesh> TryComputeLatestMeshAsync(double maxTrianglesPerCubicMeter) const;
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::Surfaces::SpatialSurfaceMesh> TryComputeLatestMeshAsync(double maxTrianglesPerCubicMeter, Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshOptions const& options) const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceInfo> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceInfo<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMesh
{
    Windows::Perception::Spatial::Surfaces::SpatialSurfaceInfo SurfaceInfo() const;
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
    Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer TriangleIndices() const;
    Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer VertexPositions() const;
    Windows::Foundation::Numerics::float3 VertexPositionScale() const;
    Windows::Perception::Spatial::Surfaces::SpatialSurfaceMeshBuffer VertexNormals() const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMesh> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMesh<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshBuffer
{
    Windows::Graphics::DirectX::DirectXPixelFormat Format() const;
    uint32_t Stride() const;
    uint32_t ElementCount() const;
    Windows::Storage::Streams::IBuffer Data() const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshBuffer> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshBuffer<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshOptions
{
    Windows::Graphics::DirectX::DirectXPixelFormat VertexPositionFormat() const;
    void VertexPositionFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const;
    Windows::Graphics::DirectX::DirectXPixelFormat TriangleIndexFormat() const;
    void TriangleIndexFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const;
    Windows::Graphics::DirectX::DirectXPixelFormat VertexNormalFormat() const;
    void VertexNormalFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const;
    bool IncludeVertexNormals() const;
    void IncludeVertexNormals(bool value) const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptions> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshOptions<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshOptionsStatics
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> SupportedVertexPositionFormats() const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> SupportedTriangleIndexFormats() const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> SupportedVertexNormalFormats() const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceMeshOptionsStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceMeshOptionsStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserver
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Perception::Spatial::Surfaces::SpatialSurfaceInfo> GetObservedSurfaces() const;
    void SetBoundingVolume(Windows::Perception::Spatial::SpatialBoundingVolume const& bounds) const;
    void SetBoundingVolumes(param::iterable<Windows::Perception::Spatial::SpatialBoundingVolume> const& bounds) const;
    winrt::event_token ObservedSurfacesChanged(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::Surfaces::SpatialSurfaceObserver, Windows::Foundation::IInspectable> const& handler) const;
    using ObservedSurfacesChanged_revoker = impl::event_revoker<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver, &impl::abi_t<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver>::remove_ObservedSurfacesChanged>;
    ObservedSurfacesChanged_revoker ObservedSurfacesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::Surfaces::SpatialSurfaceObserver, Windows::Foundation::IInspectable> const& handler) const;
    void ObservedSurfacesChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserver> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserver<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserverStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> RequestAccessAsync() const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserverStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserverStatics2
{
    bool IsSupported() const;
};
template <> struct consume<Windows::Perception::Spatial::Surfaces::ISpatialSurfaceObserverStatics2> { template <typename D> using type = consume_Windows_Perception_Spatial_Surfaces_ISpatialSurfaceObserverStatics2<D>; };

}
