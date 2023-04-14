// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.0.h"
#include "winrt/impl/Windows.Graphics.Effects.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.Core.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.UI.Composition.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct WINRT_EBO IAmbientLight :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAmbientLight>
{
    IAmbientLight(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAmbientLight2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAmbientLight2>
{
    IAmbientLight2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAnimationController :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAnimationController>
{
    IAnimationController(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAnimationControllerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAnimationControllerStatics>
{
    IAnimationControllerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAnimationObject :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAnimationObject>
{
    IAnimationObject(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAnimationPropertyInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAnimationPropertyInfo>
{
    IAnimationPropertyInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBooleanKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBooleanKeyFrameAnimation>
{
    IBooleanKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBounceScalarNaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBounceScalarNaturalMotionAnimation>
{
    IBounceScalarNaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBounceVector2NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBounceVector2NaturalMotionAnimation>
{
    IBounceVector2NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IBounceVector3NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IBounceVector3NaturalMotionAnimation>
{
    IBounceVector3NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IColorKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IColorKeyFrameAnimation>
{
    IColorKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimation>
{
    ICompositionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimation2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimation2>
{
    ICompositionAnimation2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimation3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimation3>
{
    ICompositionAnimation3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimation4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimation4>
{
    ICompositionAnimation4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimationBase :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimationBase>
{
    ICompositionAnimationBase(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimationFactory>
{
    ICompositionAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionAnimationGroup :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionAnimationGroup>,
    impl::require<ICompositionAnimationGroup, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::CompositionAnimation>>
{
    ICompositionAnimationGroup(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionBackdropBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionBackdropBrush>
{
    ICompositionBackdropBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionBatchCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionBatchCompletedEventArgs>
{
    ICompositionBatchCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionBrush>
{
    ICompositionBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionBrushFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionBrushFactory>
{
    ICompositionBrushFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionCapabilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionCapabilities>
{
    ICompositionCapabilities(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionCapabilitiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionCapabilitiesStatics>
{
    ICompositionCapabilitiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionClip :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionClip>
{
    ICompositionClip(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionClip2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionClip2>
{
    ICompositionClip2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionClipFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionClipFactory>
{
    ICompositionClipFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionColorBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionColorBrush>
{
    ICompositionColorBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionColorGradientStop :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionColorGradientStop>
{
    ICompositionColorGradientStop(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionColorGradientStopCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionColorGradientStopCollection>,
    impl::require<ICompositionColorGradientStopCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::CompositionColorGradientStop>, Windows::Foundation::Collections::IVector<Windows::UI::Composition::CompositionColorGradientStop>>
{
    ICompositionColorGradientStopCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionCommitBatch :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionCommitBatch>
{
    ICompositionCommitBatch(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionContainerShape :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionContainerShape>
{
    ICompositionContainerShape(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionDrawingSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDrawingSurface>
{
    ICompositionDrawingSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionDrawingSurface2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDrawingSurface2>
{
    ICompositionDrawingSurface2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionDrawingSurfaceFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDrawingSurfaceFactory>
{
    ICompositionDrawingSurfaceFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEasingFunction :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEasingFunction>
{
    ICompositionEasingFunction(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEasingFunctionFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEasingFunctionFactory>
{
    ICompositionEasingFunctionFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEffectBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEffectBrush>
{
    ICompositionEffectBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEffectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEffectFactory>
{
    ICompositionEffectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEffectSourceParameter :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEffectSourceParameter>,
    impl::require<ICompositionEffectSourceParameter, Windows::Graphics::Effects::IGraphicsEffectSource>
{
    ICompositionEffectSourceParameter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEffectSourceParameterFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEffectSourceParameterFactory>
{
    ICompositionEffectSourceParameterFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionEllipseGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionEllipseGeometry>
{
    ICompositionEllipseGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGeometricClip :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGeometricClip>
{
    ICompositionGeometricClip(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGeometry>
{
    ICompositionGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGeometryFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGeometryFactory>
{
    ICompositionGeometryFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGradientBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGradientBrush>
{
    ICompositionGradientBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGradientBrush2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGradientBrush2>
{
    ICompositionGradientBrush2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGradientBrushFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGradientBrushFactory>
{
    ICompositionGradientBrushFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGraphicsDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGraphicsDevice>
{
    ICompositionGraphicsDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGraphicsDevice2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGraphicsDevice2>
{
    ICompositionGraphicsDevice2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionGraphicsDevice3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionGraphicsDevice3>
{
    ICompositionGraphicsDevice3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLight :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLight>
{
    ICompositionLight(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLight2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLight2>
{
    ICompositionLight2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLight3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLight3>
{
    ICompositionLight3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLightFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLightFactory>
{
    ICompositionLightFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLineGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLineGeometry>
{
    ICompositionLineGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionLinearGradientBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionLinearGradientBrush>
{
    ICompositionLinearGradientBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionMaskBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionMaskBrush>
{
    ICompositionMaskBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionMipmapSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionMipmapSurface>
{
    ICompositionMipmapSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionNineGridBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionNineGridBrush>
{
    ICompositionNineGridBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObject :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObject>
{
    ICompositionObject(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObject2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObject2>
{
    ICompositionObject2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObject3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObject3>
{
    ICompositionObject3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObject4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObject4>
{
    ICompositionObject4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObjectFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObjectFactory>
{
    ICompositionObjectFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionObjectStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionObjectStatics>
{
    ICompositionObjectStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionPath :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionPath>
{
    ICompositionPath(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionPathFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionPathFactory>
{
    ICompositionPathFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionPathGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionPathGeometry>
{
    ICompositionPathGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadow :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadow>
{
    ICompositionProjectedShadow(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadowCaster :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadowCaster>
{
    ICompositionProjectedShadowCaster(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadowCasterCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadowCasterCollection>
{
    ICompositionProjectedShadowCasterCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadowCasterCollectionStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadowCasterCollectionStatics>
{
    ICompositionProjectedShadowCasterCollectionStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadowReceiver :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadowReceiver>
{
    ICompositionProjectedShadowReceiver(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionProjectedShadowReceiverUnorderedCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionProjectedShadowReceiverUnorderedCollection>
{
    ICompositionProjectedShadowReceiverUnorderedCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionPropertySet :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionPropertySet>
{
    ICompositionPropertySet(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionPropertySet2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionPropertySet2>
{
    ICompositionPropertySet2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionRadialGradientBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionRadialGradientBrush>
{
    ICompositionRadialGradientBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionRectangleGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionRectangleGeometry>
{
    ICompositionRectangleGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionRoundedRectangleGeometry :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionRoundedRectangleGeometry>
{
    ICompositionRoundedRectangleGeometry(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionScopedBatch :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionScopedBatch>
{
    ICompositionScopedBatch(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionShadow :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionShadow>
{
    ICompositionShadow(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionShadowFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionShadowFactory>
{
    ICompositionShadowFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionShape :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionShape>
{
    ICompositionShape(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionShapeFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionShapeFactory>
{
    ICompositionShapeFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionSpriteShape :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionSpriteShape>
{
    ICompositionSpriteShape(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionSurface>
{
    ICompositionSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionSurfaceBrush :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionSurfaceBrush>
{
    ICompositionSurfaceBrush(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionSurfaceBrush2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionSurfaceBrush2>
{
    ICompositionSurfaceBrush2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionSurfaceBrush3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionSurfaceBrush3>
{
    ICompositionSurfaceBrush3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionTarget :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionTarget>
{
    ICompositionTarget(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionTargetFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionTargetFactory>
{
    ICompositionTargetFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionTransform :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionTransform>
{
    ICompositionTransform(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionTransformFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionTransformFactory>
{
    ICompositionTransformFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionViewBox :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionViewBox>
{
    ICompositionViewBox(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionVirtualDrawingSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionVirtualDrawingSurface>
{
    ICompositionVirtualDrawingSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionVirtualDrawingSurfaceFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionVirtualDrawingSurfaceFactory>
{
    ICompositionVirtualDrawingSurfaceFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionVisualSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionVisualSurface>
{
    ICompositionVisualSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor>
{
    ICompositor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor2>
{
    ICompositor2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor3>
{
    ICompositor3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor4>
{
    ICompositor4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor5 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor5>
{
    ICompositor5(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositor6 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositor6>
{
    ICompositor6(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositorStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositorStatics>
{
    ICompositorStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositorWithProjectedShadow :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositorWithProjectedShadow>
{
    ICompositorWithProjectedShadow(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositorWithRadialGradient :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositorWithRadialGradient>
{
    ICompositorWithRadialGradient(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositorWithVisualSurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositorWithVisualSurface>
{
    ICompositorWithVisualSurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IContainerVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<IContainerVisual>
{
    IContainerVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IContainerVisualFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IContainerVisualFactory>
{
    IContainerVisualFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICubicBezierEasingFunction :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICubicBezierEasingFunction>
{
    ICubicBezierEasingFunction(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDistantLight :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDistantLight>
{
    IDistantLight(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDistantLight2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDistantLight2>
{
    IDistantLight2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDropShadow :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDropShadow>
{
    IDropShadow(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDropShadow2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDropShadow2>
{
    IDropShadow2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IExpressionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IExpressionAnimation>
{
    IExpressionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IImplicitAnimationCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IImplicitAnimationCollection>,
    impl::require<IImplicitAnimationCollection, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::UI::Composition::ICompositionAnimationBase>>, Windows::Foundation::Collections::IMap<hstring, Windows::UI::Composition::ICompositionAnimationBase>>
{
    IImplicitAnimationCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IInsetClip :
    Windows::Foundation::IInspectable,
    impl::consume_t<IInsetClip>
{
    IInsetClip(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKeyFrameAnimation>
{
    IKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKeyFrameAnimation2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKeyFrameAnimation2>
{
    IKeyFrameAnimation2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKeyFrameAnimation3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKeyFrameAnimation3>
{
    IKeyFrameAnimation3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKeyFrameAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKeyFrameAnimationFactory>
{
    IKeyFrameAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILayerVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILayerVisual>
{
    ILayerVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILayerVisual2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILayerVisual2>
{
    ILayerVisual2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILinearEasingFunction :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILinearEasingFunction>
{
    ILinearEasingFunction(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<INaturalMotionAnimation>
{
    INaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO INaturalMotionAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<INaturalMotionAnimationFactory>
{
    INaturalMotionAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPathKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPathKeyFrameAnimation>
{
    IPathKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointLight :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointLight>
{
    IPointLight(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointLight2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointLight2>
{
    IPointLight2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPointLight3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPointLight3>
{
    IPointLight3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IQuaternionKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IQuaternionKeyFrameAnimation>
{
    IQuaternionKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IRedirectVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRedirectVisual>
{
    IRedirectVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IRenderingDeviceReplacedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRenderingDeviceReplacedEventArgs>
{
    IRenderingDeviceReplacedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScalarKeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScalarKeyFrameAnimation>
{
    IScalarKeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScalarNaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScalarNaturalMotionAnimation>
{
    IScalarNaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IScalarNaturalMotionAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IScalarNaturalMotionAnimationFactory>
{
    IScalarNaturalMotionAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IShapeVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<IShapeVisual>
{
    IShapeVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpotLight :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpotLight>
{
    ISpotLight(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpotLight2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpotLight2>
{
    ISpotLight2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpotLight3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpotLight3>
{
    ISpotLight3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpringScalarNaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpringScalarNaturalMotionAnimation>
{
    ISpringScalarNaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpringVector2NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpringVector2NaturalMotionAnimation>
{
    ISpringVector2NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpringVector3NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpringVector3NaturalMotionAnimation>
{
    ISpringVector3NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpriteVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpriteVisual>
{
    ISpriteVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpriteVisual2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpriteVisual2>
{
    ISpriteVisual2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStepEasingFunction :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStepEasingFunction>
{
    IStepEasingFunction(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector2KeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector2KeyFrameAnimation>
{
    IVector2KeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector2NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector2NaturalMotionAnimation>
{
    IVector2NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector2NaturalMotionAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector2NaturalMotionAnimationFactory>
{
    IVector2NaturalMotionAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector3KeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector3KeyFrameAnimation>
{
    IVector3KeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector3NaturalMotionAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector3NaturalMotionAnimation>
{
    IVector3NaturalMotionAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector3NaturalMotionAnimationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector3NaturalMotionAnimationFactory>
{
    IVector3NaturalMotionAnimationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVector4KeyFrameAnimation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVector4KeyFrameAnimation>
{
    IVector4KeyFrameAnimation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisual :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisual>
{
    IVisual(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisual2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisual2>
{
    IVisual2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisualCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisualCollection>,
    impl::require<IVisualCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Visual>>
{
    IVisualCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisualElement :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisualElement>
{
    IVisualElement(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisualFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisualFactory>
{
    IVisualFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVisualUnorderedCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVisualUnorderedCollection>,
    impl::require<IVisualUnorderedCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Visual>>
{
    IVisualUnorderedCollection(std::nullptr_t = nullptr) noexcept {}
};

}
