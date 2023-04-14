// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.0.h"
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.UI.Composition.Scenes.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Scenes {

struct WINRT_EBO ISceneBoundingBox :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneBoundingBox>
{
    ISceneBoundingBox(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneComponent :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneComponent>
{
    ISceneComponent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneComponentCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneComponentCollection>
{
    ISceneComponentCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneComponentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneComponentFactory>
{
    ISceneComponentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMaterial :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMaterial>
{
    ISceneMaterial(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMaterialFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMaterialFactory>
{
    ISceneMaterialFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMaterialInput :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMaterialInput>
{
    ISceneMaterialInput(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMaterialInputFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMaterialInputFactory>
{
    ISceneMaterialInputFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMesh :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMesh>
{
    ISceneMesh(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMeshMaterialAttributeMap :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMeshMaterialAttributeMap>
{
    ISceneMeshMaterialAttributeMap(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMeshRendererComponent :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMeshRendererComponent>
{
    ISceneMeshRendererComponent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMeshRendererComponentStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMeshRendererComponentStatics>
{
    ISceneMeshRendererComponentStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMeshStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMeshStatics>
{
    ISceneMeshStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMetallicRoughnessMaterial :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMetallicRoughnessMaterial>
{
    ISceneMetallicRoughnessMaterial(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneMetallicRoughnessMaterialStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneMetallicRoughnessMaterialStatics>
{
    ISceneMetallicRoughnessMaterialStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneModelTransform :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneModelTransform>
{
    ISceneModelTransform(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneNode :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneNode>
{
    ISceneNode(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneNodeCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneNodeCollection>
{
    ISceneNodeCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneNodeStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneNodeStatics>
{
    ISceneNodeStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneObject :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneObject>
{
    ISceneObject(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneObjectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneObjectFactory>
{
    ISceneObjectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScenePbrMaterial :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScenePbrMaterial>
{
    IScenePbrMaterial(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScenePbrMaterialFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScenePbrMaterialFactory>
{
    IScenePbrMaterialFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneRendererComponent :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneRendererComponent>
{
    ISceneRendererComponent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneRendererComponentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneRendererComponentFactory>
{
    ISceneRendererComponentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneSurfaceMaterialInput :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneSurfaceMaterialInput>
{
    ISceneSurfaceMaterialInput(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneSurfaceMaterialInputStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneSurfaceMaterialInputStatics>
{
    ISceneSurfaceMaterialInputStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneVisual>
{
    ISceneVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISceneVisualStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISceneVisualStatics>
{
    ISceneVisualStatics(std::nullptr_t = nullptr) noexcept {}
};

}
