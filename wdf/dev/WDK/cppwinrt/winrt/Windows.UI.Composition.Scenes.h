// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Composition.Scenes.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>::Center() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneBoundingBox)->get_Center(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>::Extents() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneBoundingBox)->get_Extents(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>::Max() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneBoundingBox)->get_Max(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>::Min() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneBoundingBox)->get_Min(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>::Size() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneBoundingBox)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneComponentType consume_Windows_UI_Composition_Scenes_ISceneComponent<D>::ComponentType() const
{
    Windows::UI::Composition::Scenes::SceneComponentType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneComponent)->get_ComponentType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneBoundingBox consume_Windows_UI_Composition_Scenes_ISceneMesh<D>::Bounds() const
{
    Windows::UI::Composition::Scenes::SceneBoundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMesh)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPrimitiveTopology consume_Windows_UI_Composition_Scenes_ISceneMesh<D>::PrimitiveTopology() const
{
    Windows::Graphics::DirectX::DirectXPrimitiveTopology value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMesh)->get_PrimitiveTopology(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMesh<D>::PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMesh)->put_PrimitiveTopology(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMesh<D>::FillMeshAttribute(Windows::UI::Composition::Scenes::SceneAttributeSemantic const& semantic, Windows::Graphics::DirectX::DirectXPixelFormat const& format, Windows::Foundation::MemoryBuffer const& memory) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMesh)->FillMeshAttribute(get_abi(semantic), get_abi(format), get_abi(memory)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterial consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>::Material() const
{
    Windows::UI::Composition::Scenes::SceneMaterial value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponent)->get_Material(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>::Material(Windows::UI::Composition::Scenes::SceneMaterial const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponent)->put_Material(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMesh consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>::Mesh() const
{
    Windows::UI::Composition::Scenes::SceneMesh value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponent)->get_Mesh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>::Mesh(Windows::UI::Composition::Scenes::SceneMesh const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponent)->put_Mesh(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>::UVMappings() const
{
    Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponent)->get_UVMappings(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneMeshRendererComponent consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponentStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneMeshRendererComponent result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Scenes::SceneMesh consume_Windows_UI_Composition_Scenes_ISceneMeshStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneMesh result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMeshStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterialInput consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::BaseColorInput() const
{
    Windows::UI::Composition::Scenes::SceneMaterialInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->get_BaseColorInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::BaseColorInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->put_BaseColorInput(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float4 consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::BaseColorFactor() const
{
    Windows::Foundation::Numerics::float4 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->get_BaseColorFactor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::BaseColorFactor(Windows::Foundation::Numerics::float4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->put_BaseColorFactor(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::MetallicFactor() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->get_MetallicFactor(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::MetallicFactor(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->put_MetallicFactor(value));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterialInput consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::MetallicRoughnessInput() const
{
    Windows::UI::Composition::Scenes::SceneMaterialInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->get_MetallicRoughnessInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::MetallicRoughnessInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->put_MetallicRoughnessInput(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::RoughnessFactor() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->get_RoughnessFactor(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>::RoughnessFactor(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial)->put_RoughnessFactor(value));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterialStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Orientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Orientation(Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_Orientation(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAxis() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_RotationAxis(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::RotationAxis(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_RotationAxis(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Scale() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Scale(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Translation() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->get_Translation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>::Translation(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneModelTransform)->put_Translation(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneNodeCollection consume_Windows_UI_Composition_Scenes_ISceneNode<D>::Children() const
{
    Windows::UI::Composition::Scenes::SceneNodeCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNode)->get_Children(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneComponentCollection consume_Windows_UI_Composition_Scenes_ISceneNode<D>::Components() const
{
    Windows::UI::Composition::Scenes::SceneComponentCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNode)->get_Components(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneNode consume_Windows_UI_Composition_Scenes_ISceneNode<D>::Parent() const
{
    Windows::UI::Composition::Scenes::SceneNode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNode)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneModelTransform consume_Windows_UI_Composition_Scenes_ISceneNode<D>::Transform() const
{
    Windows::UI::Composition::Scenes::SceneModelTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNode)->get_Transform(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Scenes::SceneComponent consume_Windows_UI_Composition_Scenes_ISceneNode<D>::FindFirstComponentOfType(Windows::UI::Composition::Scenes::SceneComponentType const& value) const
{
    Windows::UI::Composition::Scenes::SceneComponent result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNode)->FindFirstComponentOfType(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Scenes::SceneNode consume_Windows_UI_Composition_Scenes_ISceneNodeStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneNode result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneNodeStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> float consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::AlphaCutoff() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_AlphaCutoff(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::AlphaCutoff(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_AlphaCutoff(value));
}

template <typename D> Windows::UI::Composition::Scenes::SceneAlphaMode consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::AlphaMode() const
{
    Windows::UI::Composition::Scenes::SceneAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_AlphaMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_AlphaMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterialInput consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::EmissiveInput() const
{
    Windows::UI::Composition::Scenes::SceneMaterialInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_EmissiveInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::EmissiveInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_EmissiveInput(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::EmissiveFactor() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_EmissiveFactor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::EmissiveFactor(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_EmissiveFactor(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::IsDoubleSided() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_IsDoubleSided(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::IsDoubleSided(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_IsDoubleSided(value));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterialInput consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::NormalInput() const
{
    Windows::UI::Composition::Scenes::SceneMaterialInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_NormalInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::NormalInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_NormalInput(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::NormalScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_NormalScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::NormalScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_NormalScale(value));
}

template <typename D> Windows::UI::Composition::Scenes::SceneMaterialInput consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::OcclusionInput() const
{
    Windows::UI::Composition::Scenes::SceneMaterialInput value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_OcclusionInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::OcclusionInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_OcclusionInput(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::OcclusionStrength() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->get_OcclusionStrength(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>::OcclusionStrength(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::IScenePbrMaterial)->put_OcclusionStrength(value));
}

template <typename D> Windows::UI::Composition::CompositionBitmapInterpolationMode consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::BitmapInterpolationMode() const
{
    Windows::UI::Composition::CompositionBitmapInterpolationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->get_BitmapInterpolationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->put_BitmapInterpolationMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ICompositionSurface consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::Surface() const
{
    Windows::UI::Composition::ICompositionSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->get_Surface(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::Surface(Windows::UI::Composition::ICompositionSurface const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->put_Surface(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneWrappingMode consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::WrappingUMode() const
{
    Windows::UI::Composition::Scenes::SceneWrappingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->get_WrappingUMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->put_WrappingUMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneWrappingMode consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::WrappingVMode() const
{
    Windows::UI::Composition::Scenes::SceneWrappingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->get_WrappingVMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>::WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput)->put_WrappingVMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInputStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Scenes::SceneNode consume_Windows_UI_Composition_Scenes_ISceneVisual<D>::Root() const
{
    Windows::UI::Composition::Scenes::SceneNode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneVisual)->get_Root(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Scenes_ISceneVisual<D>::Root(Windows::UI::Composition::Scenes::SceneNode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneVisual)->put_Root(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Scenes::SceneVisual consume_Windows_UI_Composition_Scenes_ISceneVisualStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Scenes::SceneVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Scenes::ISceneVisualStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneBoundingBox> : produce_base<D, Windows::UI::Composition::Scenes::ISceneBoundingBox>
{
    int32_t WINRT_CALL get_Center(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extents(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extents, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Extents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Max(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Max, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Max());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Min(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Min, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Min());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneComponent> : produce_base<D, Windows::UI::Composition::Scenes::ISceneComponent>
{
    int32_t WINRT_CALL get_ComponentType(Windows::UI::Composition::Scenes::SceneComponentType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComponentType, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneComponentType));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneComponentType>(this->shim().ComponentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneComponentCollection> : produce_base<D, Windows::UI::Composition::Scenes::ISceneComponentCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneComponentFactory> : produce_base<D, Windows::UI::Composition::Scenes::ISceneComponentFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMaterial> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMaterial>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMaterialFactory> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMaterialFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMaterialInput> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMaterialInput>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMaterialInputFactory> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMaterialInputFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMesh> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMesh>
{
    int32_t WINRT_CALL get_Bounds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneBoundingBox));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneBoundingBox>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimitiveTopology, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPrimitiveTopology));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPrimitiveTopology>(this->shim().PrimitiveTopology());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrimitiveTopology, WINRT_WRAP(void), Windows::Graphics::DirectX::DirectXPrimitiveTopology const&);
            this->shim().PrimitiveTopology(*reinterpret_cast<Windows::Graphics::DirectX::DirectXPrimitiveTopology const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FillMeshAttribute(Windows::UI::Composition::Scenes::SceneAttributeSemantic semantic, Windows::Graphics::DirectX::DirectXPixelFormat format, void* memory) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillMeshAttribute, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneAttributeSemantic const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Foundation::MemoryBuffer const&);
            this->shim().FillMeshAttribute(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneAttributeSemantic const*>(&semantic), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&format), *reinterpret_cast<Windows::Foundation::MemoryBuffer const*>(&memory));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMeshRendererComponent> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMeshRendererComponent>
{
    int32_t WINRT_CALL get_Material(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Material, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterial));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterial>(this->shim().Material());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Material(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Material, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterial const&);
            this->shim().Material(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterial const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mesh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mesh, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMesh));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMesh>(this->shim().Mesh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mesh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mesh, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMesh const&);
            this->shim().Mesh(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMesh const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UVMappings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UVMappings, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap>(this->shim().UVMappings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMeshRendererComponent), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneMeshRendererComponent>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMeshStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMeshStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMesh), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneMesh>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial>
{
    int32_t WINRT_CALL get_BaseColorInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseColorInput, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterialInput));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterialInput>(this->shim().BaseColorInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseColorInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseColorInput, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterialInput const&);
            this->shim().BaseColorInput(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterialInput const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseColorFactor(Windows::Foundation::Numerics::float4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseColorFactor, WINRT_WRAP(Windows::Foundation::Numerics::float4));
            *value = detach_from<Windows::Foundation::Numerics::float4>(this->shim().BaseColorFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseColorFactor(Windows::Foundation::Numerics::float4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseColorFactor, WINRT_WRAP(void), Windows::Foundation::Numerics::float4 const&);
            this->shim().BaseColorFactor(*reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MetallicFactor(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetallicFactor, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MetallicFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MetallicFactor(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetallicFactor, WINRT_WRAP(void), float);
            this->shim().MetallicFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MetallicRoughnessInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetallicRoughnessInput, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterialInput));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterialInput>(this->shim().MetallicRoughnessInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MetallicRoughnessInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetallicRoughnessInput, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterialInput const&);
            this->shim().MetallicRoughnessInput(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterialInput const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoughnessFactor(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoughnessFactor, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RoughnessFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RoughnessFactor(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoughnessFactor, WINRT_WRAP(void), float);
            this->shim().RoughnessFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneModelTransform> : produce_base<D, Windows::UI::Composition::Scenes::ISceneModelTransform>
{
    int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Orientation(Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(void), Windows::Foundation::Numerics::quaternion const&);
            this->shim().Orientation(*reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAngle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationAngle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngle, WINRT_WRAP(void), float);
            this->shim().RotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAngleInDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngleInDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RotationAngleInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationAngleInDegrees(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAngleInDegrees, WINRT_WRAP(void), float);
            this->shim().RotationAngleInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAxis(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAxis, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().RotationAxis());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationAxis(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAxis, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().RotationAxis(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Translation(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Translation, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Translation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Translation(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Translation, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Translation(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneNode> : produce_base<D, Windows::UI::Composition::Scenes::ISceneNode>
{
    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneNodeCollection));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneNodeCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Components(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneComponentCollection));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneComponentCollection>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneNode));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneNode>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneModelTransform));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneModelTransform>(this->shim().Transform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindFirstComponentOfType(Windows::UI::Composition::Scenes::SceneComponentType value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindFirstComponentOfType, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneComponent), Windows::UI::Composition::Scenes::SceneComponentType const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneComponent>(this->shim().FindFirstComponentOfType(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneComponentType const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneNodeCollection> : produce_base<D, Windows::UI::Composition::Scenes::ISceneNodeCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneNodeStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneNodeStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneNode), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneNode>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneObject> : produce_base<D, Windows::UI::Composition::Scenes::ISceneObject>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneObjectFactory> : produce_base<D, Windows::UI::Composition::Scenes::ISceneObjectFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::IScenePbrMaterial> : produce_base<D, Windows::UI::Composition::Scenes::IScenePbrMaterial>
{
    int32_t WINRT_CALL get_AlphaCutoff(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaCutoff, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().AlphaCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlphaCutoff(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaCutoff, WINRT_WRAP(void), float);
            this->shim().AlphaCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaMode, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneAlphaMode));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneAlphaMode>(this->shim().AlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaMode, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneAlphaMode const&);
            this->shim().AlphaMode(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneAlphaMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmissiveInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmissiveInput, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterialInput));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterialInput>(this->shim().EmissiveInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EmissiveInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmissiveInput, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterialInput const&);
            this->shim().EmissiveInput(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterialInput const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmissiveFactor(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmissiveFactor, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().EmissiveFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EmissiveFactor(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmissiveFactor, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().EmissiveFactor(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleSided(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleSided, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDoubleSided());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDoubleSided(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleSided, WINRT_WRAP(void), bool);
            this->shim().IsDoubleSided(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalInput, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterialInput));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterialInput>(this->shim().NormalInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalInput, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterialInput const&);
            this->shim().NormalInput(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterialInput const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().NormalScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalScale, WINRT_WRAP(void), float);
            this->shim().NormalScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OcclusionInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionInput, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneMaterialInput));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneMaterialInput>(this->shim().OcclusionInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OcclusionInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionInput, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneMaterialInput const&);
            this->shim().OcclusionInput(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneMaterialInput const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OcclusionStrength(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionStrength, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().OcclusionStrength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OcclusionStrength(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionStrength, WINRT_WRAP(void), float);
            this->shim().OcclusionStrength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::IScenePbrMaterialFactory> : produce_base<D, Windows::UI::Composition::Scenes::IScenePbrMaterialFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneRendererComponent> : produce_base<D, Windows::UI::Composition::Scenes::ISceneRendererComponent>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneRendererComponentFactory> : produce_base<D, Windows::UI::Composition::Scenes::ISceneRendererComponentFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput> : produce_base<D, Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput>
{
    int32_t WINRT_CALL get_BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapInterpolationMode, WINRT_WRAP(Windows::UI::Composition::CompositionBitmapInterpolationMode));
            *value = detach_from<Windows::UI::Composition::CompositionBitmapInterpolationMode>(this->shim().BitmapInterpolationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapInterpolationMode, WINRT_WRAP(void), Windows::UI::Composition::CompositionBitmapInterpolationMode const&);
            this->shim().BitmapInterpolationMode(*reinterpret_cast<Windows::UI::Composition::CompositionBitmapInterpolationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Surface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Surface, WINRT_WRAP(Windows::UI::Composition::ICompositionSurface));
            *value = detach_from<Windows::UI::Composition::ICompositionSurface>(this->shim().Surface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Surface(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Surface, WINRT_WRAP(void), Windows::UI::Composition::ICompositionSurface const&);
            this->shim().Surface(*reinterpret_cast<Windows::UI::Composition::ICompositionSurface const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WrappingUMode, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneWrappingMode));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneWrappingMode>(this->shim().WrappingUMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WrappingUMode, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneWrappingMode const&);
            this->shim().WrappingUMode(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneWrappingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WrappingVMode, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneWrappingMode));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneWrappingMode>(this->shim().WrappingVMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WrappingVMode, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneWrappingMode const&);
            this->shim().WrappingVMode(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneWrappingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneVisual> : produce_base<D, Windows::UI::Composition::Scenes::ISceneVisual>
{
    int32_t WINRT_CALL get_Root(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Root, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneNode));
            *value = detach_from<Windows::UI::Composition::Scenes::SceneNode>(this->shim().Root());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Root(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Root, WINRT_WRAP(void), Windows::UI::Composition::Scenes::SceneNode const&);
            this->shim().Root(*reinterpret_cast<Windows::UI::Composition::Scenes::SceneNode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Scenes::ISceneVisualStatics> : produce_base<D, Windows::UI::Composition::Scenes::ISceneVisualStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Scenes::SceneVisual), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Scenes::SceneVisual>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Scenes {

inline Windows::UI::Composition::Scenes::SceneMesh SceneMesh::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneMesh, Windows::UI::Composition::Scenes::ISceneMeshStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Scenes::SceneMeshRendererComponent SceneMeshRendererComponent::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneMeshRendererComponent, Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial SceneMetallicRoughnessMaterial::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneMetallicRoughnessMaterial, Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Scenes::SceneNode SceneNode::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneNode, Windows::UI::Composition::Scenes::ISceneNodeStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput SceneSurfaceMaterialInput::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneSurfaceMaterialInput, Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Scenes::SceneVisual SceneVisual::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<SceneVisual, Windows::UI::Composition::Scenes::ISceneVisualStatics>([&](auto&& f) { return f.Create(compositor); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneBoundingBox> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneBoundingBox> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneComponentCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneComponentCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneComponentFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneComponentFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMaterialFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMaterialFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMaterialInput> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMaterialInput> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMaterialInputFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMaterialInputFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMesh> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMesh> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMeshRendererComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMeshRendererComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMeshStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMeshStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneModelTransform> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneModelTransform> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneNode> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneNode> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneNodeCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneNodeCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneNodeStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneNodeStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneObject> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneObject> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneObjectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneObjectFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::IScenePbrMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::IScenePbrMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::IScenePbrMaterialFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::IScenePbrMaterialFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneRendererComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneRendererComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneRendererComponentFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneRendererComponentFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ISceneVisualStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ISceneVisualStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneBoundingBox> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneBoundingBox> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneComponentCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneComponentCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMaterialInput> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMaterialInput> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMesh> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMesh> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMeshRendererComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMeshRendererComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneModelTransform> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneModelTransform> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneNode> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneNode> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneNodeCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneNodeCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneObject> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneObject> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::ScenePbrMaterial> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::ScenePbrMaterial> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneRendererComponent> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneRendererComponent> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput> {};
template<> struct hash<winrt::Windows::UI::Composition::Scenes::SceneVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Scenes::SceneVisual> {};

}
