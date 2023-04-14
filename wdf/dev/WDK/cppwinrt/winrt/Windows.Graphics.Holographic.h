// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.Graphics.Holographic.2.h"
#include "winrt/Windows.Graphics.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicCamera<D>::RenderTargetSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->get_RenderTargetSize(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Graphics_Holographic_IHolographicCamera<D>::ViewportScaleFactor() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->get_ViewportScaleFactor(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCamera<D>::ViewportScaleFactor(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->put_ViewportScaleFactor(value));
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCamera<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->get_IsStereo(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Holographic_IHolographicCamera<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->get_Id(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCamera<D>::SetNearPlaneDistance(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->SetNearPlaneDistance(value));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCamera<D>::SetFarPlaneDistance(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera)->SetFarPlaneDistance(value));
}

template <typename D> Windows::Graphics::Holographic::HolographicCameraViewportParameters consume_Windows_Graphics_Holographic_IHolographicCamera2<D>::LeftViewportParameters() const
{
    Windows::Graphics::Holographic::HolographicCameraViewportParameters result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera2)->get_LeftViewportParameters(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Holographic::HolographicCameraViewportParameters consume_Windows_Graphics_Holographic_IHolographicCamera2<D>::RightViewportParameters() const
{
    Windows::Graphics::Holographic::HolographicCameraViewportParameters result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera2)->get_RightViewportParameters(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Holographic::HolographicDisplay consume_Windows_Graphics_Holographic_IHolographicCamera2<D>::Display() const
{
    Windows::Graphics::Holographic::HolographicDisplay result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera2)->get_Display(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCamera3<D>::IsPrimaryLayerEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera3)->get_IsPrimaryLayerEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCamera3<D>::IsPrimaryLayerEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera3)->put_IsPrimaryLayerEnabled(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Holographic_IHolographicCamera3<D>::MaxQuadLayerCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera3)->get_MaxQuadLayerCount(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Holographic::HolographicQuadLayer> consume_Windows_Graphics_Holographic_IHolographicCamera3<D>::QuadLayers() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Holographic::HolographicQuadLayer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera3)->get_QuadLayers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCamera4<D>::CanOverrideViewport() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera4)->get_CanOverrideViewport(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCamera5<D>::IsHardwareContentProtectionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera5)->get_IsHardwareContentProtectionSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCamera5<D>::IsHardwareContentProtectionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera5)->get_IsHardwareContentProtectionEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCamera5<D>::IsHardwareContentProtectionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera5)->put_IsHardwareContentProtectionEnabled(value));
}

template <typename D> Windows::Graphics::Holographic::HolographicViewConfiguration consume_Windows_Graphics_Holographic_IHolographicCamera6<D>::ViewConfiguration() const
{
    Windows::Graphics::Holographic::HolographicViewConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCamera6)->get_ViewConfiguration(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicCamera consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::HolographicCamera() const
{
    Windows::Graphics::Holographic::HolographicCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->get_HolographicCamera(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::Viewport() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->get_Viewport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Graphics::Holographic::HolographicStereoTransform> consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::TryGetViewTransform(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Foundation::IReference<Windows::Graphics::Holographic::HolographicStereoTransform> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->TryGetViewTransform(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicStereoTransform consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::ProjectionTransform() const
{
    Windows::Graphics::Holographic::HolographicStereoTransform value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->get_ProjectionTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::TryGetCullingFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->TryGetCullingFrustum(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::TryGetVisibleFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->TryGetVisibleFrustum(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::NearPlaneDistance() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->get_NearPlaneDistance(&value));
    return value;
}

template <typename D> double consume_Windows_Graphics_Holographic_IHolographicCameraPose<D>::FarPlaneDistance() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose)->get_FarPlaneDistance(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraPose2<D>::OverrideViewTransform(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Graphics::Holographic::HolographicStereoTransform const& coordinateSystemToViewTransform) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose2)->OverrideViewTransform(get_abi(coordinateSystem), get_abi(coordinateSystemToViewTransform)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraPose2<D>::OverrideProjectionTransform(Windows::Graphics::Holographic::HolographicStereoTransform const& projectionTransform) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose2)->OverrideProjectionTransform(get_abi(projectionTransform)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraPose2<D>::OverrideViewport(Windows::Foundation::Rect const& leftViewport, Windows::Foundation::Rect const& rightViewport) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraPose2)->OverrideViewport(get_abi(leftViewport), get_abi(rightViewport)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>::SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters)->SetFocusPoint(get_abi(coordinateSystem), get_abi(position)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>::SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::float3 const& normal) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters)->SetFocusPointWithNormal(get_abi(coordinateSystem), get_abi(position), get_abi(normal)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>::SetFocusPoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::float3 const& normal, Windows::Foundation::Numerics::float3 const& linearVelocity) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters)->SetFocusPointWithNormalLinearVelocity(get_abi(coordinateSystem), get_abi(position), get_abi(normal), get_abi(linearVelocity)));
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>::Direct3D11Device() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters)->get_Direct3D11Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters<D>::Direct3D11BackBuffer() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters)->get_Direct3D11BackBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicReprojectionMode consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters2<D>::ReprojectionMode() const
{
    Windows::Graphics::Holographic::HolographicReprojectionMode value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2)->get_ReprojectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters2<D>::ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2)->put_ReprojectionMode(get_abi(value)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters2<D>::CommitDirect3D11DepthBuffer(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2)->CommitDirect3D11DepthBuffer(get_abi(value)));
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters3<D>::IsContentProtectionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3)->get_IsContentProtectionEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicCameraRenderingParameters3<D>::IsContentProtectionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3)->put_IsContentProtectionEnabled(value));
}

template <typename D> com_array<Windows::Foundation::Numerics::float2> consume_Windows_Graphics_Holographic_IHolographicCameraViewportParameters<D>::HiddenAreaMesh() const
{
    com_array<Windows::Foundation::Numerics::float2> value;
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraViewportParameters)->get_HiddenAreaMesh(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> com_array<Windows::Foundation::Numerics::float2> consume_Windows_Graphics_Holographic_IHolographicCameraViewportParameters<D>::VisibleAreaMesh() const
{
    com_array<Windows::Foundation::Numerics::float2> value;
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicCameraViewportParameters)->get_VisibleAreaMesh(impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::MaxViewportSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_MaxViewportSize(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_IsStereo(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::IsOpaque() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_IsOpaque(&value));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicAdapterId consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::AdapterId() const
{
    Windows::Graphics::Holographic::HolographicAdapterId value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_AdapterId(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocator consume_Windows_Graphics_Holographic_IHolographicDisplay<D>::SpatialLocator() const
{
    Windows::Perception::Spatial::SpatialLocator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay)->get_SpatialLocator(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Graphics_Holographic_IHolographicDisplay2<D>::RefreshRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay2)->get_RefreshRate(&value));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicViewConfiguration consume_Windows_Graphics_Holographic_IHolographicDisplay3<D>::TryGetViewConfiguration(Windows::Graphics::Holographic::HolographicViewConfigurationKind const& kind) const
{
    Windows::Graphics::Holographic::HolographicViewConfiguration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplay3)->TryGetViewConfiguration(get_abi(kind), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Holographic::HolographicDisplay consume_Windows_Graphics_Holographic_IHolographicDisplayStatics<D>::GetDefault() const
{
    Windows::Graphics::Holographic::HolographicDisplay result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicDisplayStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> consume_Windows_Graphics_Holographic_IHolographicFrame<D>::AddedCameras() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->get_AddedCameras(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> consume_Windows_Graphics_Holographic_IHolographicFrame<D>::RemovedCameras() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->get_RemovedCameras(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicCameraRenderingParameters consume_Windows_Graphics_Holographic_IHolographicFrame<D>::GetRenderingParameters(Windows::Graphics::Holographic::HolographicCameraPose const& cameraPose) const
{
    Windows::Graphics::Holographic::HolographicCameraRenderingParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->GetRenderingParameters(get_abi(cameraPose), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Graphics_Holographic_IHolographicFrame<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicFramePrediction consume_Windows_Graphics_Holographic_IHolographicFrame<D>::CurrentPrediction() const
{
    Windows::Graphics::Holographic::HolographicFramePrediction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->get_CurrentPrediction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicFrame<D>::UpdateCurrentPrediction() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->UpdateCurrentPrediction());
}

template <typename D> Windows::Graphics::Holographic::HolographicFramePresentResult consume_Windows_Graphics_Holographic_IHolographicFrame<D>::PresentUsingCurrentPrediction() const
{
    Windows::Graphics::Holographic::HolographicFramePresentResult result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->PresentUsingCurrentPrediction(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Holographic::HolographicFramePresentResult consume_Windows_Graphics_Holographic_IHolographicFrame<D>::PresentUsingCurrentPrediction(Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior const& waitBehavior) const
{
    Windows::Graphics::Holographic::HolographicFramePresentResult result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->PresentUsingCurrentPredictionWithBehavior(get_abi(waitBehavior), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicFrame<D>::WaitForFrameToFinish() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame)->WaitForFrameToFinish());
}

template <typename D> Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters consume_Windows_Graphics_Holographic_IHolographicFrame2<D>::GetQuadLayerUpdateParameters(Windows::Graphics::Holographic::HolographicQuadLayer const& layer) const
{
    Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFrame2)->GetQuadLayerUpdateParameters(get_abi(layer), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCameraPose> consume_Windows_Graphics_Holographic_IHolographicFramePrediction<D>::CameraPoses() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCameraPose> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePrediction)->get_CameraPoses(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_Graphics_Holographic_IHolographicFramePrediction<D>::Timestamp() const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePrediction)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicFramePresentationReport> consume_Windows_Graphics_Holographic_IHolographicFramePresentationMonitor<D>::ReadReports() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicFramePresentationReport> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationMonitor)->ReadReports(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>::CompositorGpuDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationReport)->get_CompositorGpuDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>::AppGpuDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationReport)->get_AppGpuDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>::AppGpuOverrun() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationReport)->get_AppGpuOverrun(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>::MissedPresentationOpportunityCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationReport)->get_MissedPresentationOpportunityCount(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Holographic_IHolographicFramePresentationReport<D>::PresentationCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicFramePresentationReport)->get_PresentationCount(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_Graphics_Holographic_IHolographicQuadLayer<D>::PixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayer)->get_PixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicQuadLayer<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayer)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicQuadLayer consume_Windows_Graphics_Holographic_IHolographicQuadLayerFactory<D>::Create(Windows::Foundation::Size const& size) const
{
    Windows::Graphics::Holographic::HolographicQuadLayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerFactory)->Create(get_abi(size), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicQuadLayer consume_Windows_Graphics_Holographic_IHolographicQuadLayerFactory<D>::CreateWithPixelFormat(Windows::Foundation::Size const& size, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat) const
{
    Windows::Graphics::Holographic::HolographicQuadLayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerFactory)->CreateWithPixelFormat(get_abi(size), get_abi(pixelFormat), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::AcquireBufferToUpdateContent() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->AcquireBufferToUpdateContent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::UpdateViewport(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->UpdateViewport(get_abi(value)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::UpdateContentProtectionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->UpdateContentProtectionEnabled(value));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::UpdateExtents(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->UpdateExtents(get_abi(value)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::UpdateLocationWithStationaryMode(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->UpdateLocationWithStationaryMode(get_abi(coordinateSystem), get_abi(position), get_abi(orientation)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters<D>::UpdateLocationWithDisplayRelativeMode(Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters)->UpdateLocationWithDisplayRelativeMode(get_abi(position), get_abi(orientation)));
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters2<D>::CanAcquireWithHardwareProtection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2)->get_CanAcquireWithHardwareProtection(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Graphics_Holographic_IHolographicQuadLayerUpdateParameters2<D>::AcquireBufferToUpdateContentWithHardwareProtection() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2)->AcquireBufferToUpdateContentWithHardwareProtection(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicAdapterId consume_Windows_Graphics_Holographic_IHolographicSpace<D>::PrimaryAdapterId() const
{
    Windows::Graphics::Holographic::HolographicAdapterId value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->get_PrimaryAdapterId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace<D>::SetDirect3D11Device(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->SetDirect3D11Device(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraAdded(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->add_CameraAdded(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraAdded_revoker consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CameraAdded_revoker>(this, CameraAdded(handler));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraAdded(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->remove_CameraAdded(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraRemoved(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->add_CameraRemoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraRemoved_revoker consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CameraRemoved_revoker>(this, CameraRemoved(handler));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CameraRemoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->remove_CameraRemoved(get_abi(cookie)));
}

template <typename D> Windows::Graphics::Holographic::HolographicFrame consume_Windows_Graphics_Holographic_IHolographicSpace<D>::CreateNextFrame() const
{
    Windows::Graphics::Holographic::HolographicFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace)->CreateNextFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicSpaceUserPresence consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::UserPresence() const
{
    Windows::Graphics::Holographic::HolographicSpaceUserPresence value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->get_UserPresence(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::UserPresenceChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->add_UserPresenceChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::UserPresenceChanged_revoker consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::UserPresenceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UserPresenceChanged_revoker>(this, UserPresenceChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::UserPresenceChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->remove_UserPresenceChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::WaitForNextFrameReady() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->WaitForNextFrameReady());
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::WaitForNextFrameReadyWithHeadStart(Windows::Foundation::TimeSpan const& requestedHeadStartDuration) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->WaitForNextFrameReadyWithHeadStart(get_abi(requestedHeadStartDuration)));
}

template <typename D> Windows::Graphics::Holographic::HolographicFramePresentationMonitor consume_Windows_Graphics_Holographic_IHolographicSpace2<D>::CreateFramePresentationMonitor(uint32_t maxQueuedReports) const
{
    Windows::Graphics::Holographic::HolographicFramePresentationMonitor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpace2)->CreateFramePresentationMonitor(maxQueuedReports, put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Holographic::HolographicCamera consume_Windows_Graphics_Holographic_IHolographicSpaceCameraAddedEventArgs<D>::Camera() const
{
    Windows::Graphics::Holographic::HolographicCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs)->get_Camera(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Graphics_Holographic_IHolographicSpaceCameraAddedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicCamera consume_Windows_Graphics_Holographic_IHolographicSpaceCameraRemovedEventArgs<D>::Camera() const
{
    Windows::Graphics::Holographic::HolographicCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs)->get_Camera(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicSpace consume_Windows_Graphics_Holographic_IHolographicSpaceStatics<D>::CreateForCoreWindow(Windows::UI::Core::CoreWindow const& window) const
{
    Windows::Graphics::Holographic::HolographicSpace value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics)->CreateForCoreWindow(get_abi(window), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics2)->get_IsSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics2)->get_IsAvailable(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics2)->add_IsAvailableChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsAvailableChanged_revoker consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsAvailableChanged_revoker>(this, IsAvailableChanged(handler));
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicSpaceStatics2<D>::IsAvailableChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics2)->remove_IsAvailableChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicSpaceStatics3<D>::IsConfigured() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicSpaceStatics3)->get_IsConfigured(&value));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::NativeRenderTargetSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_NativeRenderTargetSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::RenderTargetSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_RenderTargetSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::RequestRenderTargetSize(Windows::Foundation::Size const& size) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->RequestRenderTargetSize(get_abi(size), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::SupportedPixelFormats() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_SupportedPixelFormats(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::PixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_PixelFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->put_PixelFormat(get_abi(value)));
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_IsStereo(&value));
    return value;
}

template <typename D> double consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::RefreshRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_RefreshRate(&value));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicViewConfigurationKind consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::Kind() const
{
    Windows::Graphics::Holographic::HolographicViewConfigurationKind value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Holographic::HolographicDisplay consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::Display() const
{
    Windows::Graphics::Holographic::HolographicDisplay value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_Display(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Holographic_IHolographicViewConfiguration<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Holographic::IHolographicViewConfiguration)->put_IsEnabled(value));
}

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera>
{
    int32_t WINRT_CALL get_RenderTargetSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTargetSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().RenderTargetSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewportScaleFactor(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportScaleFactor, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ViewportScaleFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewportScaleFactor(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewportScaleFactor, WINRT_WRAP(void), double);
            this->shim().ViewportScaleFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNearPlaneDistance(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNearPlaneDistance, WINRT_WRAP(void), double);
            this->shim().SetNearPlaneDistance(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFarPlaneDistance(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFarPlaneDistance, WINRT_WRAP(void), double);
            this->shim().SetFarPlaneDistance(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera2> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera2>
{
    int32_t WINRT_CALL get_LeftViewportParameters(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftViewportParameters, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCameraViewportParameters));
            *result = detach_from<Windows::Graphics::Holographic::HolographicCameraViewportParameters>(this->shim().LeftViewportParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightViewportParameters(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightViewportParameters, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCameraViewportParameters));
            *result = detach_from<Windows::Graphics::Holographic::HolographicCameraViewportParameters>(this->shim().RightViewportParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Display(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Display, WINRT_WRAP(Windows::Graphics::Holographic::HolographicDisplay));
            *result = detach_from<Windows::Graphics::Holographic::HolographicDisplay>(this->shim().Display());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera3> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera3>
{
    int32_t WINRT_CALL get_IsPrimaryLayerEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimaryLayerEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrimaryLayerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPrimaryLayerEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimaryLayerEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPrimaryLayerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxQuadLayerCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxQuadLayerCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxQuadLayerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QuadLayers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuadLayers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Holographic::HolographicQuadLayer>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Holographic::HolographicQuadLayer>>(this->shim().QuadLayers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera4> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera4>
{
    int32_t WINRT_CALL get_CanOverrideViewport(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanOverrideViewport, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanOverrideViewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera5> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera5>
{
    int32_t WINRT_CALL get_IsHardwareContentProtectionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHardwareContentProtectionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHardwareContentProtectionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHardwareContentProtectionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHardwareContentProtectionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHardwareContentProtectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHardwareContentProtectionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHardwareContentProtectionEnabled, WINRT_WRAP(void), bool);
            this->shim().IsHardwareContentProtectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCamera6> : produce_base<D, Windows::Graphics::Holographic::IHolographicCamera6>
{
    int32_t WINRT_CALL get_ViewConfiguration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewConfiguration, WINRT_WRAP(Windows::Graphics::Holographic::HolographicViewConfiguration));
            *value = detach_from<Windows::Graphics::Holographic::HolographicViewConfiguration>(this->shim().ViewConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraPose> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraPose>
{
    int32_t WINRT_CALL get_HolographicCamera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HolographicCamera, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCamera));
            *value = detach_from<Windows::Graphics::Holographic::HolographicCamera>(this->shim().HolographicCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Viewport(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Viewport, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Viewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetViewTransform(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetViewTransform, WINRT_WRAP(Windows::Foundation::IReference<Windows::Graphics::Holographic::HolographicStereoTransform>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Foundation::IReference<Windows::Graphics::Holographic::HolographicStereoTransform>>(this->shim().TryGetViewTransform(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionTransform(struct struct_Windows_Graphics_Holographic_HolographicStereoTransform* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionTransform, WINRT_WRAP(Windows::Graphics::Holographic::HolographicStereoTransform));
            *value = detach_from<Windows::Graphics::Holographic::HolographicStereoTransform>(this->shim().ProjectionTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetCullingFrustum(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetCullingFrustum, WINRT_WRAP(Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum>>(this->shim().TryGetCullingFrustum(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetVisibleFrustum(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetVisibleFrustum, WINRT_WRAP(Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingFrustum>>(this->shim().TryGetVisibleFrustum(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NearPlaneDistance(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NearPlaneDistance, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NearPlaneDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FarPlaneDistance(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FarPlaneDistance, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FarPlaneDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraPose2> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraPose2>
{
    int32_t WINRT_CALL OverrideViewTransform(void* coordinateSystem, struct struct_Windows_Graphics_Holographic_HolographicStereoTransform coordinateSystemToViewTransform) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverrideViewTransform, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Graphics::Holographic::HolographicStereoTransform const&);
            this->shim().OverrideViewTransform(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Graphics::Holographic::HolographicStereoTransform const*>(&coordinateSystemToViewTransform));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OverrideProjectionTransform(struct struct_Windows_Graphics_Holographic_HolographicStereoTransform projectionTransform) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverrideProjectionTransform, WINRT_WRAP(void), Windows::Graphics::Holographic::HolographicStereoTransform const&);
            this->shim().OverrideProjectionTransform(*reinterpret_cast<Windows::Graphics::Holographic::HolographicStereoTransform const*>(&projectionTransform));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OverrideViewport(Windows::Foundation::Rect leftViewport, Windows::Foundation::Rect rightViewport) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverrideViewport, WINRT_WRAP(void), Windows::Foundation::Rect const&, Windows::Foundation::Rect const&);
            this->shim().OverrideViewport(*reinterpret_cast<Windows::Foundation::Rect const*>(&leftViewport), *reinterpret_cast<Windows::Foundation::Rect const*>(&rightViewport));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>
{
    int32_t WINRT_CALL SetFocusPoint(void* coordinateSystem, Windows::Foundation::Numerics::float3 position) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFocusPoint, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().SetFocusPoint(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFocusPointWithNormal(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::float3 normal) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFocusPoint, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().SetFocusPoint(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&normal));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFocusPointWithNormalLinearVelocity(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::float3 normal, Windows::Foundation::Numerics::float3 linearVelocity) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFocusPoint, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().SetFocusPoint(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&normal), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&linearVelocity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direct3D11Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3D11Device, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>(this->shim().Direct3D11Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direct3D11BackBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3D11BackBuffer, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3D11BackBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>
{
    int32_t WINRT_CALL get_ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReprojectionMode, WINRT_WRAP(Windows::Graphics::Holographic::HolographicReprojectionMode));
            *value = detach_from<Windows::Graphics::Holographic::HolographicReprojectionMode>(this->shim().ReprojectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReprojectionMode(Windows::Graphics::Holographic::HolographicReprojectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReprojectionMode, WINRT_WRAP(void), Windows::Graphics::Holographic::HolographicReprojectionMode const&);
            this->shim().ReprojectionMode(*reinterpret_cast<Windows::Graphics::Holographic::HolographicReprojectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CommitDirect3D11DepthBuffer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitDirect3D11DepthBuffer, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const&);
            this->shim().CommitDirect3D11DepthBuffer(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3>
{
    int32_t WINRT_CALL get_IsContentProtectionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentProtectionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsContentProtectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsContentProtectionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentProtectionEnabled, WINRT_WRAP(void), bool);
            this->shim().IsContentProtectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicCameraViewportParameters> : produce_base<D, Windows::Graphics::Holographic::IHolographicCameraViewportParameters>
{
    int32_t WINRT_CALL get_HiddenAreaMesh(uint32_t* __valueSize, Windows::Foundation::Numerics::float2** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HiddenAreaMesh, WINRT_WRAP(com_array<Windows::Foundation::Numerics::float2>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().HiddenAreaMesh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibleAreaMesh(uint32_t* __valueSize, Windows::Foundation::Numerics::float2** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleAreaMesh, WINRT_WRAP(com_array<Windows::Foundation::Numerics::float2>));
            std::tie(*__valueSize, *value) = detach_abi(this->shim().VisibleAreaMesh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicDisplay> : produce_base<D, Windows::Graphics::Holographic::IHolographicDisplay>
{
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

    int32_t WINRT_CALL get_MaxViewportSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxViewportSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MaxViewportSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOpaque(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOpaque, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOpaque());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdapterId(struct struct_Windows_Graphics_Holographic_HolographicAdapterId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdapterId, WINRT_WRAP(Windows::Graphics::Holographic::HolographicAdapterId));
            *value = detach_from<Windows::Graphics::Holographic::HolographicAdapterId>(this->shim().AdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpatialLocator(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatialLocator, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocator));
            *value = detach_from<Windows::Perception::Spatial::SpatialLocator>(this->shim().SpatialLocator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicDisplay2> : produce_base<D, Windows::Graphics::Holographic::IHolographicDisplay2>
{
    int32_t WINRT_CALL get_RefreshRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RefreshRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RefreshRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicDisplay3> : produce_base<D, Windows::Graphics::Holographic::IHolographicDisplay3>
{
    int32_t WINRT_CALL TryGetViewConfiguration(Windows::Graphics::Holographic::HolographicViewConfigurationKind kind, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetViewConfiguration, WINRT_WRAP(Windows::Graphics::Holographic::HolographicViewConfiguration), Windows::Graphics::Holographic::HolographicViewConfigurationKind const&);
            *result = detach_from<Windows::Graphics::Holographic::HolographicViewConfiguration>(this->shim().TryGetViewConfiguration(*reinterpret_cast<Windows::Graphics::Holographic::HolographicViewConfigurationKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicDisplayStatics> : produce_base<D, Windows::Graphics::Holographic::IHolographicDisplayStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Graphics::Holographic::HolographicDisplay));
            *result = detach_from<Windows::Graphics::Holographic::HolographicDisplay>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicFrame> : produce_base<D, Windows::Graphics::Holographic::IHolographicFrame>
{
    int32_t WINRT_CALL get_AddedCameras(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddedCameras, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera>>(this->shim().AddedCameras());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemovedCameras(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovedCameras, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCamera>>(this->shim().RemovedCameras());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRenderingParameters(void* cameraPose, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRenderingParameters, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCameraRenderingParameters), Windows::Graphics::Holographic::HolographicCameraPose const&);
            *value = detach_from<Windows::Graphics::Holographic::HolographicCameraRenderingParameters>(this->shim().GetRenderingParameters(*reinterpret_cast<Windows::Graphics::Holographic::HolographicCameraPose const*>(&cameraPose)));
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

    int32_t WINRT_CALL get_CurrentPrediction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPrediction, WINRT_WRAP(Windows::Graphics::Holographic::HolographicFramePrediction));
            *value = detach_from<Windows::Graphics::Holographic::HolographicFramePrediction>(this->shim().CurrentPrediction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateCurrentPrediction() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateCurrentPrediction, WINRT_WRAP(void));
            this->shim().UpdateCurrentPrediction();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PresentUsingCurrentPrediction(Windows::Graphics::Holographic::HolographicFramePresentResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentUsingCurrentPrediction, WINRT_WRAP(Windows::Graphics::Holographic::HolographicFramePresentResult));
            *result = detach_from<Windows::Graphics::Holographic::HolographicFramePresentResult>(this->shim().PresentUsingCurrentPrediction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PresentUsingCurrentPredictionWithBehavior(Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior waitBehavior, Windows::Graphics::Holographic::HolographicFramePresentResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentUsingCurrentPrediction, WINRT_WRAP(Windows::Graphics::Holographic::HolographicFramePresentResult), Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior const&);
            *result = detach_from<Windows::Graphics::Holographic::HolographicFramePresentResult>(this->shim().PresentUsingCurrentPrediction(*reinterpret_cast<Windows::Graphics::Holographic::HolographicFramePresentWaitBehavior const*>(&waitBehavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForFrameToFinish() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForFrameToFinish, WINRT_WRAP(void));
            this->shim().WaitForFrameToFinish();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicFrame2> : produce_base<D, Windows::Graphics::Holographic::IHolographicFrame2>
{
    int32_t WINRT_CALL GetQuadLayerUpdateParameters(void* layer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetQuadLayerUpdateParameters, WINRT_WRAP(Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters), Windows::Graphics::Holographic::HolographicQuadLayer const&);
            *value = detach_from<Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters>(this->shim().GetQuadLayerUpdateParameters(*reinterpret_cast<Windows::Graphics::Holographic::HolographicQuadLayer const*>(&layer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicFramePrediction> : produce_base<D, Windows::Graphics::Holographic::IHolographicFramePrediction>
{
    int32_t WINRT_CALL get_CameraPoses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraPoses, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCameraPose>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicCameraPose>>(this->shim().CameraPoses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Perception::PerceptionTimestamp));
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicFramePresentationMonitor> : produce_base<D, Windows::Graphics::Holographic::IHolographicFramePresentationMonitor>
{
    int32_t WINRT_CALL ReadReports(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadReports, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicFramePresentationReport>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Holographic::HolographicFramePresentationReport>>(this->shim().ReadReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicFramePresentationReport> : produce_base<D, Windows::Graphics::Holographic::IHolographicFramePresentationReport>
{
    int32_t WINRT_CALL get_CompositorGpuDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositorGpuDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().CompositorGpuDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppGpuDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppGpuDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AppGpuDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppGpuOverrun(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppGpuOverrun, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().AppGpuOverrun());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MissedPresentationOpportunityCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MissedPresentationOpportunityCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MissedPresentationOpportunityCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PresentationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicQuadLayer> : produce_base<D, Windows::Graphics::Holographic::IHolographicQuadLayer>
{
    int32_t WINRT_CALL get_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelFormat, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPixelFormat));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().PixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicQuadLayerFactory> : produce_base<D, Windows::Graphics::Holographic::IHolographicQuadLayerFactory>
{
    int32_t WINRT_CALL Create(Windows::Foundation::Size size, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Holographic::HolographicQuadLayer), Windows::Foundation::Size const&);
            *value = detach_from<Windows::Graphics::Holographic::HolographicQuadLayer>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPixelFormat(Windows::Foundation::Size size, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPixelFormat, WINRT_WRAP(Windows::Graphics::Holographic::HolographicQuadLayer), Windows::Foundation::Size const&, Windows::Graphics::DirectX::DirectXPixelFormat const&);
            *value = detach_from<Windows::Graphics::Holographic::HolographicQuadLayer>(this->shim().CreateWithPixelFormat(*reinterpret_cast<Windows::Foundation::Size const*>(&size), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters> : produce_base<D, Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters>
{
    int32_t WINRT_CALL AcquireBufferToUpdateContent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquireBufferToUpdateContent, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().AcquireBufferToUpdateContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateViewport(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateViewport, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().UpdateViewport(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateContentProtectionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateContentProtectionEnabled, WINRT_WRAP(void), bool);
            this->shim().UpdateContentProtectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateExtents(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateExtents, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().UpdateExtents(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateLocationWithStationaryMode(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateLocationWithStationaryMode, WINRT_WRAP(void), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            this->shim().UpdateLocationWithStationaryMode(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&orientation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateLocationWithDisplayRelativeMode(Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateLocationWithDisplayRelativeMode, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            this->shim().UpdateLocationWithDisplayRelativeMode(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&orientation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2> : produce_base<D, Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2>
{
    int32_t WINRT_CALL get_CanAcquireWithHardwareProtection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanAcquireWithHardwareProtection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanAcquireWithHardwareProtection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcquireBufferToUpdateContentWithHardwareProtection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquireBufferToUpdateContentWithHardwareProtection, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().AcquireBufferToUpdateContentWithHardwareProtection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpace> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpace>
{
    int32_t WINRT_CALL get_PrimaryAdapterId(struct struct_Windows_Graphics_Holographic_HolographicAdapterId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimaryAdapterId, WINRT_WRAP(Windows::Graphics::Holographic::HolographicAdapterId));
            *value = detach_from<Windows::Graphics::Holographic::HolographicAdapterId>(this->shim().PrimaryAdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDirect3D11Device(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDirect3D11Device, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&);
            this->shim().SetDirect3D11Device(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CameraAdded(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().CameraAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CameraAdded(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CameraAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CameraAdded(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_CameraRemoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().CameraRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CameraRemoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CameraRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CameraRemoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL CreateNextFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNextFrame, WINRT_WRAP(Windows::Graphics::Holographic::HolographicFrame));
            *value = detach_from<Windows::Graphics::Holographic::HolographicFrame>(this->shim().CreateNextFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpace2> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpace2>
{
    int32_t WINRT_CALL get_UserPresence(Windows::Graphics::Holographic::HolographicSpaceUserPresence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserPresence, WINRT_WRAP(Windows::Graphics::Holographic::HolographicSpaceUserPresence));
            *value = detach_from<Windows::Graphics::Holographic::HolographicSpaceUserPresence>(this->shim().UserPresence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UserPresenceChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserPresenceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserPresenceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Holographic::HolographicSpace, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserPresenceChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserPresenceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserPresenceChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL WaitForNextFrameReady() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForNextFrameReady, WINRT_WRAP(void));
            this->shim().WaitForNextFrameReady();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForNextFrameReadyWithHeadStart(Windows::Foundation::TimeSpan requestedHeadStartDuration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForNextFrameReadyWithHeadStart, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().WaitForNextFrameReadyWithHeadStart(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&requestedHeadStartDuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFramePresentationMonitor(uint32_t maxQueuedReports, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFramePresentationMonitor, WINRT_WRAP(Windows::Graphics::Holographic::HolographicFramePresentationMonitor), uint32_t);
            *result = detach_from<Windows::Graphics::Holographic::HolographicFramePresentationMonitor>(this->shim().CreateFramePresentationMonitor(maxQueuedReports));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs>
{
    int32_t WINRT_CALL get_Camera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Camera, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCamera));
            *value = detach_from<Windows::Graphics::Holographic::HolographicCamera>(this->shim().Camera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs>
{
    int32_t WINRT_CALL get_Camera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Camera, WINRT_WRAP(Windows::Graphics::Holographic::HolographicCamera));
            *value = detach_from<Windows::Graphics::Holographic::HolographicCamera>(this->shim().Camera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpaceStatics> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpaceStatics>
{
    int32_t WINRT_CALL CreateForCoreWindow(void* window, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForCoreWindow, WINRT_WRAP(Windows::Graphics::Holographic::HolographicSpace), Windows::UI::Core::CoreWindow const&);
            *value = detach_from<Windows::Graphics::Holographic::HolographicSpace>(this->shim().CreateForCoreWindow(*reinterpret_cast<Windows::UI::Core::CoreWindow const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpaceStatics2> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpaceStatics2>
{
    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsAvailableChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailableChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsAvailableChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsAvailableChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsAvailableChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsAvailableChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicSpaceStatics3> : produce_base<D, Windows::Graphics::Holographic::IHolographicSpaceStatics3>
{
    int32_t WINRT_CALL get_IsConfigured(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConfigured, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConfigured());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Holographic::IHolographicViewConfiguration> : produce_base<D, Windows::Graphics::Holographic::IHolographicViewConfiguration>
{
    int32_t WINRT_CALL get_NativeRenderTargetSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NativeRenderTargetSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().NativeRenderTargetSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderTargetSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTargetSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().RenderTargetSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestRenderTargetSize(Windows::Foundation::Size size, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRenderTargetSize, WINRT_WRAP(Windows::Foundation::Size), Windows::Foundation::Size const&);
            *result = detach_from<Windows::Foundation::Size>(this->shim().RequestRenderTargetSize(*reinterpret_cast<Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedPixelFormats(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPixelFormats, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::DirectX::DirectXPixelFormat>>(this->shim().SupportedPixelFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelFormat, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPixelFormat));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().PixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelFormat, WINRT_WRAP(void), Windows::Graphics::DirectX::DirectXPixelFormat const&);
            this->shim().PixelFormat(*reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RefreshRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RefreshRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RefreshRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Graphics::Holographic::HolographicViewConfigurationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Graphics::Holographic::HolographicViewConfigurationKind));
            *value = detach_from<Windows::Graphics::Holographic::HolographicViewConfigurationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Display(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Display, WINRT_WRAP(Windows::Graphics::Holographic::HolographicDisplay));
            *value = detach_from<Windows::Graphics::Holographic::HolographicDisplay>(this->shim().Display());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Holographic {

inline Windows::Graphics::Holographic::HolographicDisplay HolographicDisplay::GetDefault()
{
    return impl::call_factory<HolographicDisplay, Windows::Graphics::Holographic::IHolographicDisplayStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline HolographicQuadLayer::HolographicQuadLayer(Windows::Foundation::Size const& size) :
    HolographicQuadLayer(impl::call_factory<HolographicQuadLayer, Windows::Graphics::Holographic::IHolographicQuadLayerFactory>([&](auto&& f) { return f.Create(size); }))
{}

inline HolographicQuadLayer::HolographicQuadLayer(Windows::Foundation::Size const& size, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat) :
    HolographicQuadLayer(impl::call_factory<HolographicQuadLayer, Windows::Graphics::Holographic::IHolographicQuadLayerFactory>([&](auto&& f) { return f.CreateWithPixelFormat(size, pixelFormat); }))
{}

inline Windows::Graphics::Holographic::HolographicSpace HolographicSpace::CreateForCoreWindow(Windows::UI::Core::CoreWindow const& window)
{
    return impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics>([&](auto&& f) { return f.CreateForCoreWindow(window); });
}

inline bool HolographicSpace::IsSupported()
{
    return impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics2>([&](auto&& f) { return f.IsSupported(); });
}

inline bool HolographicSpace::IsAvailable()
{
    return impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics2>([&](auto&& f) { return f.IsAvailable(); });
}

inline winrt::event_token HolographicSpace::IsAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics2>([&](auto&& f) { return f.IsAvailableChanged(handler); });
}

inline HolographicSpace::IsAvailableChanged_revoker HolographicSpace::IsAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics2>();
    return { f, f.IsAvailableChanged(handler) };
}

inline void HolographicSpace::IsAvailableChanged(winrt::event_token const& token)
{
    impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics2>([&](auto&& f) { return f.IsAvailableChanged(token); });
}

inline bool HolographicSpace::IsConfigured()
{
    return impl::call_factory<HolographicSpace, Windows::Graphics::Holographic::IHolographicSpaceStatics3>([&](auto&& f) { return f.IsConfigured(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera3> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera3> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera4> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera4> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera5> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera5> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCamera6> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCamera6> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraPose> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraPose> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraPose2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraPose2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicCameraViewportParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicCameraViewportParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicDisplay> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicDisplay> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicDisplay2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicDisplay2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicDisplay3> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicDisplay3> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicDisplayStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicDisplayStatics> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicFrame> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicFrame2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicFrame2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicFramePrediction> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicFramePrediction> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicFramePresentationMonitor> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicFramePresentationMonitor> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicFramePresentationReport> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicFramePresentationReport> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicQuadLayer> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicQuadLayer> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerFactory> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicQuadLayerUpdateParameters2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpace> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpace> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpace2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpace2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpaceCameraAddedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpaceCameraRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics2> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics2> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics3> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicSpaceStatics3> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::IHolographicViewConfiguration> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::IHolographicViewConfiguration> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicCamera> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicCamera> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicCameraPose> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicCameraPose> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicCameraRenderingParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicCameraRenderingParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicCameraViewportParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicCameraViewportParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicDisplay> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicDisplay> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicFrame> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicFramePrediction> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicFramePrediction> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicFramePresentationMonitor> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicFramePresentationMonitor> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicFramePresentationReport> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicFramePresentationReport> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicQuadLayer> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicQuadLayer> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicQuadLayerUpdateParameters> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicSpace> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicSpace> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicSpaceCameraAddedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicSpaceCameraRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Holographic::HolographicViewConfiguration> : winrt::impl::hash_base<winrt::Windows::Graphics::Holographic::HolographicViewConfiguration> {};

}
