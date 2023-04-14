// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct MemoryBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX {

enum class DirectXPixelFormat;
enum class DirectXPrimitiveTopology;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

enum class CompositionBitmapInterpolationMode;
struct Compositor;
struct ICompositionSurface;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Scenes {

enum class SceneAlphaMode : int32_t
{
    Opaque = 0,
    AlphaTest = 1,
    Blend = 2,
};

enum class SceneAttributeSemantic : int32_t
{
    Index = 0,
    Vertex = 1,
    Normal = 2,
    TexCoord0 = 3,
    TexCoord1 = 4,
    Color = 5,
    Tangent = 6,
};

enum class SceneComponentType : int32_t
{
    MeshRendererComponent = 0,
};

enum class SceneWrappingMode : int32_t
{
    ClampToEdge = 0,
    MirroredRepeat = 1,
    Repeat = 2,
};

struct ISceneBoundingBox;
struct ISceneComponent;
struct ISceneComponentCollection;
struct ISceneComponentFactory;
struct ISceneMaterial;
struct ISceneMaterialFactory;
struct ISceneMaterialInput;
struct ISceneMaterialInputFactory;
struct ISceneMesh;
struct ISceneMeshMaterialAttributeMap;
struct ISceneMeshRendererComponent;
struct ISceneMeshRendererComponentStatics;
struct ISceneMeshStatics;
struct ISceneMetallicRoughnessMaterial;
struct ISceneMetallicRoughnessMaterialStatics;
struct ISceneModelTransform;
struct ISceneNode;
struct ISceneNodeCollection;
struct ISceneNodeStatics;
struct ISceneObject;
struct ISceneObjectFactory;
struct IScenePbrMaterial;
struct IScenePbrMaterialFactory;
struct ISceneRendererComponent;
struct ISceneRendererComponentFactory;
struct ISceneSurfaceMaterialInput;
struct ISceneSurfaceMaterialInputStatics;
struct ISceneVisual;
struct ISceneVisualStatics;
struct SceneBoundingBox;
struct SceneComponent;
struct SceneComponentCollection;
struct SceneMaterial;
struct SceneMaterialInput;
struct SceneMesh;
struct SceneMeshMaterialAttributeMap;
struct SceneMeshRendererComponent;
struct SceneMetallicRoughnessMaterial;
struct SceneModelTransform;
struct SceneNode;
struct SceneNodeCollection;
struct SceneObject;
struct ScenePbrMaterial;
struct SceneRendererComponent;
struct SceneSurfaceMaterialInput;
struct SceneVisual;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Composition::Scenes::ISceneBoundingBox>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneComponent>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneComponentCollection>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneComponentFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMaterial>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMaterialFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMaterialInput>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMaterialInputFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMesh>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMeshRendererComponent>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMeshStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneModelTransform>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneNode>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneNodeCollection>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneNodeStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneObject>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneObjectFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::IScenePbrMaterial>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::IScenePbrMaterialFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneRendererComponent>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneRendererComponentFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneVisual>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::ISceneVisualStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneBoundingBox>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneComponent>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneComponentCollection>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMaterial>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMaterialInput>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMesh>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMeshRendererComponent>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneModelTransform>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneNode>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneNodeCollection>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneObject>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::ScenePbrMaterial>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneRendererComponent>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneVisual>{ using type = class_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneAlphaMode>{ using type = enum_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneAttributeSemantic>{ using type = enum_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneComponentType>{ using type = enum_category; };
template <> struct category<Windows::UI::Composition::Scenes::SceneWrappingMode>{ using type = enum_category; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneBoundingBox>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneBoundingBox" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneComponentCollection>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneComponentCollection" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneComponentFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneComponentFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMaterialFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMaterialFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMaterialInput>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMaterialInput" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMaterialInputFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMaterialInputFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMesh>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMesh" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMeshMaterialAttributeMap" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMeshRendererComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMeshRendererComponentStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMeshStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMeshStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneMetallicRoughnessMaterialStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneModelTransform>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneModelTransform" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneNode>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneNode" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneNodeCollection>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneNodeCollection" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneNodeStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneNodeStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneObject>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneObject" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneObjectFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneObjectFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::IScenePbrMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.IScenePbrMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::IScenePbrMaterialFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.IScenePbrMaterialFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneRendererComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneRendererComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneRendererComponentFactory>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneRendererComponentFactory" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInput" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneSurfaceMaterialInputStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneVisual>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneVisual" }; };
template <> struct name<Windows::UI::Composition::Scenes::ISceneVisualStatics>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ISceneVisualStatics" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneBoundingBox>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneBoundingBox" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneComponentCollection>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneComponentCollection" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMaterialInput>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMaterialInput" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMesh>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMesh" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMeshMaterialAttributeMap" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMeshRendererComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMeshRendererComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneMetallicRoughnessMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneModelTransform>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneModelTransform" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneNode>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneNode" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneNodeCollection>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneNodeCollection" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneObject>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneObject" }; };
template <> struct name<Windows::UI::Composition::Scenes::ScenePbrMaterial>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.ScenePbrMaterial" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneRendererComponent>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneRendererComponent" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneSurfaceMaterialInput" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneVisual>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneVisual" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneAlphaMode>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneAlphaMode" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneAttributeSemantic>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneAttributeSemantic" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneComponentType>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneComponentType" }; };
template <> struct name<Windows::UI::Composition::Scenes::SceneWrappingMode>{ static constexpr auto & value{ L"Windows.UI.Composition.Scenes.SceneWrappingMode" }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneBoundingBox>{ static constexpr guid value{ 0x5D8FFC70,0xC618,0x4083,{ 0x82,0x51,0x99,0x62,0x59,0x31,0x14,0xAA } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneComponent>{ static constexpr guid value{ 0xAE20FC96,0x226C,0x44BD,{ 0x95,0xCB,0xDD,0x5E,0xD9,0xEB,0xE9,0xA5 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneComponentCollection>{ static constexpr guid value{ 0xC483791C,0x5F46,0x45E4,{ 0xB6,0x66,0xA3,0xD2,0x25,0x9F,0x9B,0x2E } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneComponentFactory>{ static constexpr guid value{ 0x5FBC5574,0xDDD8,0x5889,{ 0xAB,0x5B,0xD8,0xFA,0x71,0x6E,0x7C,0x9E } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMaterial>{ static constexpr guid value{ 0x8CA74B7C,0x30DF,0x4E07,{ 0x94,0x90,0x37,0x87,0x5A,0xF1,0xA1,0x23 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMaterialFactory>{ static constexpr guid value{ 0x67536C19,0xA707,0x5254,{ 0xA4,0x95,0x7F,0xDC,0x79,0x98,0x93,0xB9 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMaterialInput>{ static constexpr guid value{ 0x422A1642,0x1EF1,0x485C,{ 0x97,0xE9,0xAE,0x6F,0x95,0xAD,0x81,0x2F } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMaterialInputFactory>{ static constexpr guid value{ 0xA88FEB74,0x7D0A,0x5E4C,{ 0xA7,0x48,0x10,0x15,0xAF,0x9C,0xA7,0x4F } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMesh>{ static constexpr guid value{ 0xEE9A1530,0x1155,0x4C0C,{ 0x92,0xBD,0x40,0x02,0x0C,0xF7,0x83,0x47 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap>{ static constexpr guid value{ 0xCE843171,0x3D43,0x4855,{ 0xAA,0x69,0x31,0xFF,0x98,0x8D,0x04,0x9D } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMeshRendererComponent>{ static constexpr guid value{ 0x9929F7E3,0x6364,0x477E,{ 0x98,0xFE,0x74,0xED,0x9F,0xD4,0xC2,0xDE } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>{ static constexpr guid value{ 0x4954F37A,0x4459,0x4521,{ 0xBD,0x6E,0x2B,0x38,0xB8,0xD7,0x11,0xEA } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMeshStatics>{ static constexpr guid value{ 0x8412316C,0x7B57,0x473F,{ 0x96,0x6B,0x81,0xDC,0x27,0x7B,0x17,0x51 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial>{ static constexpr guid value{ 0xC1D91446,0x799C,0x429E,{ 0xA4,0xE4,0x5D,0xA6,0x45,0xF1,0x8E,0x61 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>{ static constexpr guid value{ 0x3BDDCA50,0x6D9D,0x4531,{ 0x8D,0xC4,0xB2,0x7E,0x3E,0x49,0xB7,0xAB } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneModelTransform>{ static constexpr guid value{ 0xC05576C2,0x32B1,0x4269,{ 0x98,0x0D,0xB9,0x85,0x37,0x10,0x0A,0xE4 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneNode>{ static constexpr guid value{ 0xACF2C247,0xF307,0x4581,{ 0x9C,0x41,0xAF,0x2E,0x29,0xC3,0xB0,0x16 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneNodeCollection>{ static constexpr guid value{ 0x29ADA101,0x2DD9,0x4332,{ 0xBE,0x63,0x60,0xD2,0xCF,0x42,0x69,0xF2 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneNodeStatics>{ static constexpr guid value{ 0x579A0FAA,0xBE9D,0x4210,{ 0x90,0x8C,0x93,0xD1,0x5F,0xEE,0xD0,0xB7 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneObject>{ static constexpr guid value{ 0x1E94249B,0x0F1B,0x49EB,{ 0xA8,0x19,0x87,0x7D,0x84,0x50,0x00,0x5B } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneObjectFactory>{ static constexpr guid value{ 0x14FE799A,0x33E4,0x52EF,{ 0x95,0x6C,0x44,0x22,0x9D,0x21,0xF2,0xC1 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::IScenePbrMaterial>{ static constexpr guid value{ 0xAAB6EBBE,0xD680,0x46DF,{ 0x82,0x94,0xB6,0x80,0x0A,0x9F,0x95,0xE7 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::IScenePbrMaterialFactory>{ static constexpr guid value{ 0x2E3F3DFE,0x0B85,0x5727,{ 0xB5,0xBE,0xB7,0xD3,0xCB,0xAC,0x37,0xFA } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneRendererComponent>{ static constexpr guid value{ 0xF1ACB857,0xCF4F,0x4025,{ 0x9B,0x25,0xA2,0xD1,0x94,0x4C,0xF5,0x07 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneRendererComponentFactory>{ static constexpr guid value{ 0x1DB6ED6C,0xAA2C,0x5967,{ 0x90,0x35,0x56,0x35,0x2D,0xC6,0x96,0x58 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput>{ static constexpr guid value{ 0x9937DA5C,0xA9CA,0x4CFC,{ 0xB3,0xAA,0x08,0x83,0x56,0x51,0x87,0x42 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>{ static constexpr guid value{ 0x5A2394D3,0x6429,0x4589,{ 0xBB,0xCF,0xB8,0x4F,0x4F,0x3C,0xFB,0xFE } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneVisual>{ static constexpr guid value{ 0x8E672C1E,0xD734,0x47B1,{ 0xBE,0x14,0x3D,0x69,0x4F,0xFA,0x43,0x01 } }; };
template <> struct guid_storage<Windows::UI::Composition::Scenes::ISceneVisualStatics>{ static constexpr guid value{ 0xB8347E9A,0x50AA,0x4527,{ 0x8D,0x34,0xDE,0x4C,0xB8,0xEA,0x88,0xB4 } }; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneBoundingBox>{ using type = Windows::UI::Composition::Scenes::ISceneBoundingBox; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneComponent>{ using type = Windows::UI::Composition::Scenes::ISceneComponent; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneComponentCollection>{ using type = Windows::Foundation::Collections::IVector<Windows::UI::Composition::Scenes::SceneComponent>; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMaterial>{ using type = Windows::UI::Composition::Scenes::ISceneMaterial; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMaterialInput>{ using type = Windows::UI::Composition::Scenes::ISceneMaterialInput; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMesh>{ using type = Windows::UI::Composition::Scenes::ISceneMesh; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap>{ using type = Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMeshRendererComponent>{ using type = Windows::UI::Composition::Scenes::ISceneMeshRendererComponent; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial>{ using type = Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneModelTransform>{ using type = Windows::UI::Composition::Scenes::ISceneModelTransform; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneNode>{ using type = Windows::UI::Composition::Scenes::ISceneNode; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneNodeCollection>{ using type = Windows::Foundation::Collections::IVector<Windows::UI::Composition::Scenes::SceneNode>; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneObject>{ using type = Windows::UI::Composition::Scenes::ISceneObject; };
template <> struct default_interface<Windows::UI::Composition::Scenes::ScenePbrMaterial>{ using type = Windows::UI::Composition::Scenes::IScenePbrMaterial; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneRendererComponent>{ using type = Windows::UI::Composition::Scenes::ISceneRendererComponent; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput>{ using type = Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput; };
template <> struct default_interface<Windows::UI::Composition::Scenes::SceneVisual>{ using type = Windows::UI::Composition::Scenes::ISceneVisual; };

template <> struct abi<Windows::UI::Composition::Scenes::ISceneBoundingBox>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Center(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Extents(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Max(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Min(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float3* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneComponent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ComponentType(Windows::UI::Composition::Scenes::SceneComponentType* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneComponentCollection>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneComponentFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMaterial>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMaterialFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMaterialInput>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMaterialInputFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMesh>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Bounds(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology value) noexcept = 0;
    virtual int32_t WINRT_CALL FillMeshAttribute(Windows::UI::Composition::Scenes::SceneAttributeSemantic semantic, Windows::Graphics::DirectX::DirectXPixelFormat format, void* memory) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMeshRendererComponent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Material(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Material(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mesh(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mesh(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UVMappings(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMeshStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BaseColorInput(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BaseColorInput(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BaseColorFactor(Windows::Foundation::Numerics::float4* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BaseColorFactor(Windows::Foundation::Numerics::float4 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MetallicFactor(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MetallicFactor(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MetallicRoughnessInput(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MetallicRoughnessInput(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoughnessFactor(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RoughnessFactor(float value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneModelTransform>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Orientation(Windows::Foundation::Numerics::quaternion value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationAngle(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationAngle(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationAngleInDegrees(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationAngleInDegrees(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationAxis(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationAxis(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Translation(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Translation(Windows::Foundation::Numerics::float3 value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneNode>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Children(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Components(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Transform(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindFirstComponentOfType(Windows::UI::Composition::Scenes::SceneComponentType value, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneNodeCollection>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneNodeStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneObject>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneObjectFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::IScenePbrMaterial>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AlphaCutoff(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlphaCutoff(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EmissiveInput(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EmissiveInput(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EmissiveFactor(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EmissiveFactor(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDoubleSided(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDoubleSided(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NormalInput(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NormalInput(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NormalScale(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NormalScale(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OcclusionInput(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OcclusionInput(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OcclusionStrength(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OcclusionStrength(float value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::IScenePbrMaterialFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneRendererComponent>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneRendererComponentFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Surface(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Surface(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneVisual>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Root(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Root(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Composition::Scenes::ISceneVisualStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* compositor, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneBoundingBox
{
    Windows::Foundation::Numerics::float3 Center() const;
    Windows::Foundation::Numerics::float3 Extents() const;
    Windows::Foundation::Numerics::float3 Max() const;
    Windows::Foundation::Numerics::float3 Min() const;
    Windows::Foundation::Numerics::float3 Size() const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneBoundingBox> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneBoundingBox<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneComponent
{
    Windows::UI::Composition::Scenes::SceneComponentType ComponentType() const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneComponent> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneComponent<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneComponentCollection
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneComponentCollection> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneComponentCollection<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneComponentFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneComponentFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneComponentFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMaterial
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMaterial> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMaterial<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMaterialFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMaterialFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMaterialFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMaterialInput
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMaterialInput> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMaterialInput<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMaterialInputFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMaterialInputFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMaterialInputFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMesh
{
    Windows::UI::Composition::Scenes::SceneBoundingBox Bounds() const;
    Windows::Graphics::DirectX::DirectXPrimitiveTopology PrimitiveTopology() const;
    void PrimitiveTopology(Windows::Graphics::DirectX::DirectXPrimitiveTopology const& value) const;
    void FillMeshAttribute(Windows::UI::Composition::Scenes::SceneAttributeSemantic const& semantic, Windows::Graphics::DirectX::DirectXPixelFormat const& format, Windows::Foundation::MemoryBuffer const& memory) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMesh> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMesh<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMeshMaterialAttributeMap
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMeshMaterialAttributeMap> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMeshMaterialAttributeMap<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent
{
    Windows::UI::Composition::Scenes::SceneMaterial Material() const;
    void Material(Windows::UI::Composition::Scenes::SceneMaterial const& value) const;
    Windows::UI::Composition::Scenes::SceneMesh Mesh() const;
    void Mesh(Windows::UI::Composition::Scenes::SceneMesh const& value) const;
    Windows::UI::Composition::Scenes::SceneMeshMaterialAttributeMap UVMappings() const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMeshRendererComponent> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponent<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponentStatics
{
    Windows::UI::Composition::Scenes::SceneMeshRendererComponent Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMeshRendererComponentStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMeshRendererComponentStatics<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMeshStatics
{
    Windows::UI::Composition::Scenes::SceneMesh Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMeshStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMeshStatics<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial
{
    Windows::UI::Composition::Scenes::SceneMaterialInput BaseColorInput() const;
    void BaseColorInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const;
    Windows::Foundation::Numerics::float4 BaseColorFactor() const;
    void BaseColorFactor(Windows::Foundation::Numerics::float4 const& value) const;
    float MetallicFactor() const;
    void MetallicFactor(float value) const;
    Windows::UI::Composition::Scenes::SceneMaterialInput MetallicRoughnessInput() const;
    void MetallicRoughnessInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const;
    float RoughnessFactor() const;
    void RoughnessFactor(float value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterial> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterial<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterialStatics
{
    Windows::UI::Composition::Scenes::SceneMetallicRoughnessMaterial Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneMetallicRoughnessMaterialStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneMetallicRoughnessMaterialStatics<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneModelTransform
{
    Windows::Foundation::Numerics::quaternion Orientation() const;
    void Orientation(Windows::Foundation::Numerics::quaternion const& value) const;
    float RotationAngle() const;
    void RotationAngle(float value) const;
    float RotationAngleInDegrees() const;
    void RotationAngleInDegrees(float value) const;
    Windows::Foundation::Numerics::float3 RotationAxis() const;
    void RotationAxis(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Foundation::Numerics::float3 Scale() const;
    void Scale(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Foundation::Numerics::float3 Translation() const;
    void Translation(Windows::Foundation::Numerics::float3 const& value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneModelTransform> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneModelTransform<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneNode
{
    Windows::UI::Composition::Scenes::SceneNodeCollection Children() const;
    Windows::UI::Composition::Scenes::SceneComponentCollection Components() const;
    Windows::UI::Composition::Scenes::SceneNode Parent() const;
    Windows::UI::Composition::Scenes::SceneModelTransform Transform() const;
    Windows::UI::Composition::Scenes::SceneComponent FindFirstComponentOfType(Windows::UI::Composition::Scenes::SceneComponentType const& value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneNode> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneNode<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneNodeCollection
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneNodeCollection> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneNodeCollection<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneNodeStatics
{
    Windows::UI::Composition::Scenes::SceneNode Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneNodeStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneNodeStatics<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneObject
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneObject> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneObject<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneObjectFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneObjectFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneObjectFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_IScenePbrMaterial
{
    float AlphaCutoff() const;
    void AlphaCutoff(float value) const;
    Windows::UI::Composition::Scenes::SceneAlphaMode AlphaMode() const;
    void AlphaMode(Windows::UI::Composition::Scenes::SceneAlphaMode const& value) const;
    Windows::UI::Composition::Scenes::SceneMaterialInput EmissiveInput() const;
    void EmissiveInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const;
    Windows::Foundation::Numerics::float3 EmissiveFactor() const;
    void EmissiveFactor(Windows::Foundation::Numerics::float3 const& value) const;
    bool IsDoubleSided() const;
    void IsDoubleSided(bool value) const;
    Windows::UI::Composition::Scenes::SceneMaterialInput NormalInput() const;
    void NormalInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const;
    float NormalScale() const;
    void NormalScale(float value) const;
    Windows::UI::Composition::Scenes::SceneMaterialInput OcclusionInput() const;
    void OcclusionInput(Windows::UI::Composition::Scenes::SceneMaterialInput const& value) const;
    float OcclusionStrength() const;
    void OcclusionStrength(float value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::IScenePbrMaterial> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_IScenePbrMaterial<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_IScenePbrMaterialFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::IScenePbrMaterialFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_IScenePbrMaterialFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneRendererComponent
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneRendererComponent> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneRendererComponent<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneRendererComponentFactory
{
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneRendererComponentFactory> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneRendererComponentFactory<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput
{
    Windows::UI::Composition::CompositionBitmapInterpolationMode BitmapInterpolationMode() const;
    void BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode const& value) const;
    Windows::UI::Composition::ICompositionSurface Surface() const;
    void Surface(Windows::UI::Composition::ICompositionSurface const& value) const;
    Windows::UI::Composition::Scenes::SceneWrappingMode WrappingUMode() const;
    void WrappingUMode(Windows::UI::Composition::Scenes::SceneWrappingMode const& value) const;
    Windows::UI::Composition::Scenes::SceneWrappingMode WrappingVMode() const;
    void WrappingVMode(Windows::UI::Composition::Scenes::SceneWrappingMode const& value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInput> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInput<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInputStatics
{
    Windows::UI::Composition::Scenes::SceneSurfaceMaterialInput Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneSurfaceMaterialInputStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneSurfaceMaterialInputStatics<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneVisual
{
    Windows::UI::Composition::Scenes::SceneNode Root() const;
    void Root(Windows::UI::Composition::Scenes::SceneNode const& value) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneVisual> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneVisual<D>; };

template <typename D>
struct consume_Windows_UI_Composition_Scenes_ISceneVisualStatics
{
    Windows::UI::Composition::Scenes::SceneVisual Create(Windows::UI::Composition::Compositor const& compositor) const;
};
template <> struct consume<Windows::UI::Composition::Scenes::ISceneVisualStatics> { template <typename D> using type = consume_Windows_UI_Composition_Scenes_ISceneVisualStatics<D>; };

}
