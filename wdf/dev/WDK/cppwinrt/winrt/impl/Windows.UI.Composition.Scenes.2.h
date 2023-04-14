// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.UI.Composition.Scenes.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Scenes {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Scenes {

struct WINRT_EBO SceneBoundingBox :
    Windows::UI::Composition::Scenes::ISceneBoundingBox,
    impl::base<SceneBoundingBox, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneBoundingBox, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneBoundingBox(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneComponent :
    Windows::UI::Composition::Scenes::ISceneComponent,
    impl::base<SceneComponent, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneComponent, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneComponent(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneComponentCollection :
    Windows::Foundation::Collections::IVector<Windows::UI::Composition::Scenes::SceneComponent>,
    impl::base<SceneComponentCollection, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneComponentCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneComponentCollection, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneComponentCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneMaterial :
    Windows::UI::Composition::Scenes::ISceneMaterial,
    impl::base<SceneMaterial, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMaterial, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneMaterial(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneMaterialInput :
    Windows::UI::Composition::Scenes::ISceneMaterialInput,
    impl::base<SceneMaterialInput, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMaterialInput, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneMaterialInput(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneMesh :
    Windows::UI::Composition::Scenes::ISceneMesh,
    impl::base<SceneMesh, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMesh, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneMesh(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneMesh Create(Windows::UI::Composition::Compositor const& compositor);
};

struct WINRT_EBO SceneMeshMaterialAttributeMap :
    Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap,
    impl::base<SceneMeshMaterialAttributeMap, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMeshMaterialAttributeMap, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::UI::Composition::Scenes::SceneAttributeSemantic>>, Windows::Foundation::Collections::IMap<hstring, Windows::UI::Composition::Scenes::SceneAttributeSemantic>, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneMeshMaterialAttributeMap(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneMeshRendererComponent :
    Windows::UI::Composition::Scenes::ISceneMeshRendererComponent,
    impl::base<SceneMeshRendererComponent, Windows::UI::Composition::Scenes::SceneRendererComponent, Windows::UI::Composition::Scenes::SceneComponent, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMeshRendererComponent, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneComponent, Windows::UI::Composition::Scenes::ISceneObject, Windows::UI::Composition::Scenes::ISceneRendererComponent>
{
    SceneMeshRendererComponent(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneMeshRendererComponent Create(Windows::UI::Composition::Compositor const& compositor);
};

struct WINRT_EBO SceneMetallicRoughnessMaterial :
    Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial,
    impl::base<SceneMetallicRoughnessMaterial, Windows::UI::Composition::Scenes::ScenePbrMaterial, Windows::UI::Composition::Scenes::SceneMaterial, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneMetallicRoughnessMaterial, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneMaterial, Windows::UI::Composition::Scenes::ISceneObject, Windows::UI::Composition::Scenes::IScenePbrMaterial>
{
    SceneMetallicRoughnessMaterial(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial Create(Windows::UI::Composition::Compositor const& compositor);
};

struct WINRT_EBO SceneModelTransform :
    Windows::UI::Composition::Scenes::ISceneModelTransform,
    impl::base<SceneModelTransform, Windows::UI::Composition::CompositionTransform, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneModelTransform, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionTransform>
{
    SceneModelTransform(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneNode :
    Windows::UI::Composition::Scenes::ISceneNode,
    impl::base<SceneNode, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneNode, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneNode(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneNode Create(Windows::UI::Composition::Compositor const& compositor);
};

struct WINRT_EBO SceneNodeCollection :
    Windows::Foundation::Collections::IVector<Windows::UI::Composition::Scenes::SceneNode>,
    impl::base<SceneNodeCollection, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneNodeCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneNodeCollection, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneNodeCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneObject :
    Windows::UI::Composition::Scenes::ISceneObject,
    impl::base<SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneObject, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    SceneObject(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ScenePbrMaterial :
    Windows::UI::Composition::Scenes::IScenePbrMaterial,
    impl::base<ScenePbrMaterial, Windows::UI::Composition::Scenes::SceneMaterial, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<ScenePbrMaterial, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneMaterial, Windows::UI::Composition::Scenes::ISceneObject>
{
    ScenePbrMaterial(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneRendererComponent :
    Windows::UI::Composition::Scenes::ISceneRendererComponent,
    impl::base<SceneRendererComponent, Windows::UI::Composition::Scenes::SceneComponent, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneRendererComponent, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneComponent, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneRendererComponent(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SceneSurfaceMaterialInput :
    Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput,
    impl::base<SceneSurfaceMaterialInput, Windows::UI::Composition::Scenes::SceneMaterialInput, Windows::UI::Composition::Scenes::SceneObject, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneSurfaceMaterialInput, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::Scenes::ISceneMaterialInput, Windows::UI::Composition::Scenes::ISceneObject>
{
    SceneSurfaceMaterialInput(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput Create(Windows::UI::Composition::Compositor const& compositor);
};

struct WINRT_EBO SceneVisual :
    Windows::UI::Composition::Scenes::ISceneVisual,
    impl::base<SceneVisual, Windows::UI::Composition::ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<SceneVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IContainerVisual, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    SceneVisual(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Scenes::SceneVisual Create(Windows::UI::Composition::Compositor const& compositor);
};

}
