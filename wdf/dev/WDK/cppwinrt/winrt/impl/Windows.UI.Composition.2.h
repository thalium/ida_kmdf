// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Graphics.Effects.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Core.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct WINRT_EBO AmbientLight :
    Windows::UI::Composition::IAmbientLight,
    impl::base<AmbientLight, Windows::UI::Composition::CompositionLight, Windows::UI::Composition::CompositionObject>,
    impl::require<AmbientLight, Windows::Foundation::IClosable, Windows::UI::Composition::IAmbientLight2, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionLight, Windows::UI::Composition::ICompositionLight2, Windows::UI::Composition::ICompositionLight3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    AmbientLight(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AnimationController :
    Windows::UI::Composition::IAnimationController,
    impl::base<AnimationController, Windows::UI::Composition::CompositionObject>,
    impl::require<AnimationController, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    AnimationController(std::nullptr_t) noexcept {}
    static float MaxPlaybackRate();
    static float MinPlaybackRate();
};

struct WINRT_EBO AnimationPropertyInfo :
    Windows::UI::Composition::IAnimationPropertyInfo,
    impl::base<AnimationPropertyInfo, Windows::UI::Composition::CompositionObject>,
    impl::require<AnimationPropertyInfo, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    AnimationPropertyInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BooleanKeyFrameAnimation :
    Windows::UI::Composition::IBooleanKeyFrameAnimation,
    impl::base<BooleanKeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<BooleanKeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    BooleanKeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BounceScalarNaturalMotionAnimation :
    Windows::UI::Composition::IBounceScalarNaturalMotionAnimation,
    impl::base<BounceScalarNaturalMotionAnimation, Windows::UI::Composition::ScalarNaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<BounceScalarNaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IScalarNaturalMotionAnimation>
{
    BounceScalarNaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BounceVector2NaturalMotionAnimation :
    Windows::UI::Composition::IBounceVector2NaturalMotionAnimation,
    impl::base<BounceVector2NaturalMotionAnimation, Windows::UI::Composition::Vector2NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<BounceVector2NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IVector2NaturalMotionAnimation>
{
    BounceVector2NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BounceVector3NaturalMotionAnimation :
    Windows::UI::Composition::IBounceVector3NaturalMotionAnimation,
    impl::base<BounceVector3NaturalMotionAnimation, Windows::UI::Composition::Vector3NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<BounceVector3NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IVector3NaturalMotionAnimation>
{
    BounceVector3NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ColorKeyFrameAnimation :
    Windows::UI::Composition::IColorKeyFrameAnimation,
    impl::base<ColorKeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<ColorKeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    ColorKeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionAnimation :
    Windows::UI::Composition::ICompositionAnimation,
    impl::base<CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionAnimationGroup :
    Windows::UI::Composition::ICompositionAnimationGroup,
    impl::base<CompositionAnimationGroup, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionAnimationGroup, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionAnimationGroup(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionBackdropBrush :
    Windows::UI::Composition::ICompositionBackdropBrush,
    impl::base<CompositionBackdropBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionBackdropBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionBackdropBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionBatchCompletedEventArgs :
    Windows::UI::Composition::ICompositionBatchCompletedEventArgs,
    impl::base<CompositionBatchCompletedEventArgs, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionBatchCompletedEventArgs, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionBatchCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionBrush :
    Windows::UI::Composition::ICompositionBrush,
    impl::base<CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionCapabilities :
    Windows::UI::Composition::ICompositionCapabilities
{
    CompositionCapabilities(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::CompositionCapabilities GetForCurrentView();
};

struct WINRT_EBO CompositionClip :
    Windows::UI::Composition::ICompositionClip,
    impl::base<CompositionClip, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionClip, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionClip2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionClip(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionColorBrush :
    Windows::UI::Composition::ICompositionColorBrush,
    impl::base<CompositionColorBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionColorBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionColorBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionColorGradientStop :
    Windows::UI::Composition::ICompositionColorGradientStop,
    impl::base<CompositionColorGradientStop, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionColorGradientStop, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionColorGradientStop(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionColorGradientStopCollection :
    Windows::UI::Composition::ICompositionColorGradientStopCollection
{
    CompositionColorGradientStopCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionCommitBatch :
    Windows::UI::Composition::ICompositionCommitBatch,
    impl::base<CompositionCommitBatch, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionCommitBatch, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionCommitBatch(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionContainerShape :
    Windows::UI::Composition::ICompositionContainerShape,
    impl::base<CompositionContainerShape, Windows::UI::Composition::CompositionShape, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionContainerShape, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionShape>
{
    CompositionContainerShape(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionDrawingSurface :
    Windows::UI::Composition::ICompositionDrawingSurface,
    impl::base<CompositionDrawingSurface, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionDrawingSurface, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionDrawingSurface2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionSurface>
{
    CompositionDrawingSurface(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionEasingFunction :
    Windows::UI::Composition::ICompositionEasingFunction,
    impl::base<CompositionEasingFunction, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionEasingFunction, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionEasingFunction(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionEffectBrush :
    Windows::UI::Composition::ICompositionEffectBrush,
    impl::base<CompositionEffectBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionEffectBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionEffectBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionEffectFactory :
    Windows::UI::Composition::ICompositionEffectFactory,
    impl::base<CompositionEffectFactory, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionEffectFactory, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionEffectFactory(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionEffectSourceParameter :
    Windows::UI::Composition::ICompositionEffectSourceParameter
{
    CompositionEffectSourceParameter(std::nullptr_t) noexcept {}
    CompositionEffectSourceParameter(param::hstring const& name);
};

struct WINRT_EBO CompositionEllipseGeometry :
    Windows::UI::Composition::ICompositionEllipseGeometry,
    impl::base<CompositionEllipseGeometry, Windows::UI::Composition::CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionEllipseGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGeometry, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionEllipseGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionGeometricClip :
    Windows::UI::Composition::ICompositionGeometricClip,
    impl::base<CompositionGeometricClip, Windows::UI::Composition::CompositionClip, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionGeometricClip, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionClip, Windows::UI::Composition::ICompositionClip2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionGeometricClip(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionGeometry :
    Windows::UI::Composition::ICompositionGeometry,
    impl::base<CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionGradientBrush :
    Windows::UI::Composition::ICompositionGradientBrush,
    impl::base<CompositionGradientBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionGradientBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionGradientBrush2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionGradientBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionGraphicsDevice :
    Windows::UI::Composition::ICompositionGraphicsDevice,
    impl::base<CompositionGraphicsDevice, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionGraphicsDevice, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGraphicsDevice2, Windows::UI::Composition::ICompositionGraphicsDevice3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionGraphicsDevice(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionLight :
    Windows::UI::Composition::ICompositionLight,
    impl::base<CompositionLight, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionLight, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionLight2, Windows::UI::Composition::ICompositionLight3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionLight(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionLineGeometry :
    Windows::UI::Composition::ICompositionLineGeometry,
    impl::base<CompositionLineGeometry, Windows::UI::Composition::CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionLineGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGeometry, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionLineGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionLinearGradientBrush :
    Windows::UI::Composition::ICompositionLinearGradientBrush,
    impl::base<CompositionLinearGradientBrush, Windows::UI::Composition::CompositionGradientBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionLinearGradientBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionGradientBrush, Windows::UI::Composition::ICompositionGradientBrush2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionLinearGradientBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionMaskBrush :
    Windows::UI::Composition::ICompositionMaskBrush,
    impl::base<CompositionMaskBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionMaskBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionMaskBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionMipmapSurface :
    Windows::UI::Composition::ICompositionMipmapSurface,
    impl::base<CompositionMipmapSurface, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionMipmapSurface, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionSurface>
{
    CompositionMipmapSurface(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionNineGridBrush :
    Windows::UI::Composition::ICompositionNineGridBrush,
    impl::base<CompositionNineGridBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionNineGridBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionNineGridBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionObject :
    Windows::UI::Composition::ICompositionObject,
    impl::require<CompositionObject, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionObject(std::nullptr_t) noexcept {}
    static void StartAnimationWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, param::hstring const& propertyName, Windows::UI::Composition::CompositionAnimation const& animation);
    static void StartAnimationGroupWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, Windows::UI::Composition::ICompositionAnimationBase const& animation);
};

struct WINRT_EBO CompositionPath :
    Windows::UI::Composition::ICompositionPath,
    impl::require<CompositionPath, Windows::Graphics::IGeometrySource2D>
{
    CompositionPath(std::nullptr_t) noexcept {}
    CompositionPath(Windows::Graphics::IGeometrySource2D const& source);
};

struct WINRT_EBO CompositionPathGeometry :
    Windows::UI::Composition::ICompositionPathGeometry,
    impl::base<CompositionPathGeometry, Windows::UI::Composition::CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionPathGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGeometry, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionPathGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionProjectedShadow :
    Windows::UI::Composition::ICompositionProjectedShadow,
    impl::base<CompositionProjectedShadow, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionProjectedShadow, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionProjectedShadow(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionProjectedShadowCaster :
    Windows::UI::Composition::ICompositionProjectedShadowCaster,
    impl::base<CompositionProjectedShadowCaster, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionProjectedShadowCaster, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionProjectedShadowCaster(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionProjectedShadowCasterCollection :
    Windows::UI::Composition::ICompositionProjectedShadowCasterCollection,
    impl::base<CompositionProjectedShadowCasterCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionProjectedShadowCasterCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::CompositionProjectedShadowCaster>, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionProjectedShadowCasterCollection(std::nullptr_t) noexcept {}
    static int32_t MaxRespectedCasters();
};

struct WINRT_EBO CompositionProjectedShadowReceiver :
    Windows::UI::Composition::ICompositionProjectedShadowReceiver,
    impl::base<CompositionProjectedShadowReceiver, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionProjectedShadowReceiver, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionProjectedShadowReceiver(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionProjectedShadowReceiverUnorderedCollection :
    Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection,
    impl::base<CompositionProjectedShadowReceiverUnorderedCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionProjectedShadowReceiverUnorderedCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Composition::CompositionProjectedShadowReceiver>, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionProjectedShadowReceiverUnorderedCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionPropertySet :
    Windows::UI::Composition::ICompositionPropertySet,
    impl::base<CompositionPropertySet, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionPropertySet, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionPropertySet2>
{
    CompositionPropertySet(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionRadialGradientBrush :
    Windows::UI::Composition::ICompositionRadialGradientBrush,
    impl::base<CompositionRadialGradientBrush, Windows::UI::Composition::CompositionGradientBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionRadialGradientBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionGradientBrush, Windows::UI::Composition::ICompositionGradientBrush2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionRadialGradientBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionRectangleGeometry :
    Windows::UI::Composition::ICompositionRectangleGeometry,
    impl::base<CompositionRectangleGeometry, Windows::UI::Composition::CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionRectangleGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGeometry, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionRectangleGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionRoundedRectangleGeometry :
    Windows::UI::Composition::ICompositionRoundedRectangleGeometry,
    impl::base<CompositionRoundedRectangleGeometry, Windows::UI::Composition::CompositionGeometry, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionRoundedRectangleGeometry, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionGeometry, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionRoundedRectangleGeometry(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionScopedBatch :
    Windows::UI::Composition::ICompositionScopedBatch,
    impl::base<CompositionScopedBatch, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionScopedBatch, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionScopedBatch(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionShadow :
    Windows::UI::Composition::ICompositionShadow,
    impl::base<CompositionShadow, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionShadow, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionShadow(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionShape :
    Windows::UI::Composition::ICompositionShape,
    impl::base<CompositionShape, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionShape, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionShape(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionShapeCollection :
    Windows::Foundation::Collections::IVector<Windows::UI::Composition::CompositionShape>,
    impl::base<CompositionShapeCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionShapeCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionShapeCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionSpriteShape :
    Windows::UI::Composition::ICompositionSpriteShape,
    impl::base<CompositionSpriteShape, Windows::UI::Composition::CompositionShape, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionSpriteShape, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionShape>
{
    CompositionSpriteShape(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionStrokeDashArray :
    Windows::Foundation::Collections::IVector<float>,
    impl::base<CompositionStrokeDashArray, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionStrokeDashArray, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionStrokeDashArray(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionSurfaceBrush :
    Windows::UI::Composition::ICompositionSurfaceBrush,
    impl::base<CompositionSurfaceBrush, Windows::UI::Composition::CompositionBrush, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionSurfaceBrush, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionBrush, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionSurfaceBrush2, Windows::UI::Composition::ICompositionSurfaceBrush3>
{
    CompositionSurfaceBrush(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionTarget :
    Windows::UI::Composition::ICompositionTarget,
    impl::base<CompositionTarget, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionTarget, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionTarget(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionTransform :
    Windows::UI::Composition::ICompositionTransform,
    impl::base<CompositionTransform, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionTransform, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionTransform(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionViewBox :
    Windows::UI::Composition::ICompositionViewBox,
    impl::base<CompositionViewBox, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionViewBox, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CompositionViewBox(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionVirtualDrawingSurface :
    Windows::UI::Composition::ICompositionVirtualDrawingSurface,
    impl::base<CompositionVirtualDrawingSurface, Windows::UI::Composition::CompositionDrawingSurface, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionVirtualDrawingSurface, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionDrawingSurface, Windows::UI::Composition::ICompositionDrawingSurface2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionSurface>
{
    CompositionVirtualDrawingSurface(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionVisualSurface :
    Windows::UI::Composition::ICompositionVisualSurface,
    impl::base<CompositionVisualSurface, Windows::UI::Composition::CompositionObject>,
    impl::require<CompositionVisualSurface, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionSurface>
{
    CompositionVisualSurface(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Compositor :
    Windows::UI::Composition::ICompositor,
    impl::require<Compositor, Windows::Foundation::IClosable, Windows::UI::Composition::ICompositor2, Windows::UI::Composition::ICompositor3, Windows::UI::Composition::ICompositor4, Windows::UI::Composition::ICompositor5, Windows::UI::Composition::ICompositor6, Windows::UI::Composition::ICompositorWithProjectedShadow, Windows::UI::Composition::ICompositorWithRadialGradient, Windows::UI::Composition::ICompositorWithVisualSurface>
{
    Compositor(std::nullptr_t) noexcept {}
    Compositor();
    static float MaxGlobalPlaybackRate();
    static float MinGlobalPlaybackRate();
};

struct WINRT_EBO ContainerVisual :
    Windows::UI::Composition::IContainerVisual,
    impl::base<ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<ContainerVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    ContainerVisual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CubicBezierEasingFunction :
    Windows::UI::Composition::ICubicBezierEasingFunction,
    impl::base<CubicBezierEasingFunction, Windows::UI::Composition::CompositionEasingFunction, Windows::UI::Composition::CompositionObject>,
    impl::require<CubicBezierEasingFunction, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionEasingFunction, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    CubicBezierEasingFunction(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DistantLight :
    Windows::UI::Composition::IDistantLight,
    impl::base<DistantLight, Windows::UI::Composition::CompositionLight, Windows::UI::Composition::CompositionObject>,
    impl::require<DistantLight, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionLight, Windows::UI::Composition::ICompositionLight2, Windows::UI::Composition::ICompositionLight3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IDistantLight2>
{
    DistantLight(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DropShadow :
    Windows::UI::Composition::IDropShadow,
    impl::base<DropShadow, Windows::UI::Composition::CompositionShadow, Windows::UI::Composition::CompositionObject>,
    impl::require<DropShadow, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionShadow, Windows::UI::Composition::IDropShadow2>
{
    DropShadow(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ExpressionAnimation :
    Windows::UI::Composition::IExpressionAnimation,
    impl::base<ExpressionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<ExpressionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    ExpressionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ImplicitAnimationCollection :
    Windows::UI::Composition::IImplicitAnimationCollection,
    impl::base<ImplicitAnimationCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<ImplicitAnimationCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    ImplicitAnimationCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InitialValueExpressionCollection :
    Windows::Foundation::Collections::IMap<hstring, hstring>,
    impl::base<InitialValueExpressionCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<InitialValueExpressionCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    InitialValueExpressionCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InsetClip :
    Windows::UI::Composition::IInsetClip,
    impl::base<InsetClip, Windows::UI::Composition::CompositionClip, Windows::UI::Composition::CompositionObject>,
    impl::require<InsetClip, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionClip, Windows::UI::Composition::ICompositionClip2, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    InsetClip(std::nullptr_t) noexcept {}
};

struct WINRT_EBO KeyFrameAnimation :
    Windows::UI::Composition::IKeyFrameAnimation,
    impl::base<KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<KeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    KeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LayerVisual :
    Windows::UI::Composition::ILayerVisual,
    impl::base<LayerVisual, Windows::UI::Composition::ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<LayerVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IContainerVisual, Windows::UI::Composition::ILayerVisual2, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    LayerVisual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LinearEasingFunction :
    Windows::UI::Composition::ILinearEasingFunction,
    impl::base<LinearEasingFunction, Windows::UI::Composition::CompositionEasingFunction, Windows::UI::Composition::CompositionObject>,
    impl::require<LinearEasingFunction, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionEasingFunction, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    LinearEasingFunction(std::nullptr_t) noexcept {}
};

struct WINRT_EBO NaturalMotionAnimation :
    Windows::UI::Composition::INaturalMotionAnimation,
    impl::base<NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PathKeyFrameAnimation :
    Windows::UI::Composition::IPathKeyFrameAnimation,
    impl::base<PathKeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<PathKeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    PathKeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PointLight :
    Windows::UI::Composition::IPointLight,
    impl::base<PointLight, Windows::UI::Composition::CompositionLight, Windows::UI::Composition::CompositionObject>,
    impl::require<PointLight, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionLight, Windows::UI::Composition::ICompositionLight2, Windows::UI::Composition::ICompositionLight3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IPointLight2, Windows::UI::Composition::IPointLight3>
{
    PointLight(std::nullptr_t) noexcept {}
};

struct WINRT_EBO QuaternionKeyFrameAnimation :
    Windows::UI::Composition::IQuaternionKeyFrameAnimation,
    impl::base<QuaternionKeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<QuaternionKeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    QuaternionKeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RedirectVisual :
    Windows::UI::Composition::IRedirectVisual,
    impl::base<RedirectVisual, Windows::UI::Composition::ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<RedirectVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IContainerVisual, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    RedirectVisual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RenderingDeviceReplacedEventArgs :
    Windows::UI::Composition::IRenderingDeviceReplacedEventArgs,
    impl::base<RenderingDeviceReplacedEventArgs, Windows::UI::Composition::CompositionObject>,
    impl::require<RenderingDeviceReplacedEventArgs, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    RenderingDeviceReplacedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ScalarKeyFrameAnimation :
    Windows::UI::Composition::IScalarKeyFrameAnimation,
    impl::base<ScalarKeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<ScalarKeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    ScalarKeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ScalarNaturalMotionAnimation :
    Windows::UI::Composition::IScalarNaturalMotionAnimation,
    impl::base<ScalarNaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<ScalarNaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation>
{
    ScalarNaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShapeVisual :
    Windows::UI::Composition::IShapeVisual,
    impl::base<ShapeVisual, Windows::UI::Composition::ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<ShapeVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IContainerVisual, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    ShapeVisual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SpotLight :
    Windows::UI::Composition::ISpotLight,
    impl::base<SpotLight, Windows::UI::Composition::CompositionLight, Windows::UI::Composition::CompositionObject>,
    impl::require<SpotLight, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionLight, Windows::UI::Composition::ICompositionLight2, Windows::UI::Composition::ICompositionLight3, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ISpotLight2, Windows::UI::Composition::ISpotLight3>
{
    SpotLight(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SpringScalarNaturalMotionAnimation :
    Windows::UI::Composition::ISpringScalarNaturalMotionAnimation,
    impl::base<SpringScalarNaturalMotionAnimation, Windows::UI::Composition::ScalarNaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<SpringScalarNaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IScalarNaturalMotionAnimation>
{
    SpringScalarNaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SpringVector2NaturalMotionAnimation :
    Windows::UI::Composition::ISpringVector2NaturalMotionAnimation,
    impl::base<SpringVector2NaturalMotionAnimation, Windows::UI::Composition::Vector2NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<SpringVector2NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IVector2NaturalMotionAnimation>
{
    SpringVector2NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SpringVector3NaturalMotionAnimation :
    Windows::UI::Composition::ISpringVector3NaturalMotionAnimation,
    impl::base<SpringVector3NaturalMotionAnimation, Windows::UI::Composition::Vector3NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<SpringVector3NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation, Windows::UI::Composition::IVector3NaturalMotionAnimation>
{
    SpringVector3NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SpriteVisual :
    Windows::UI::Composition::ISpriteVisual,
    impl::base<SpriteVisual, Windows::UI::Composition::ContainerVisual, Windows::UI::Composition::Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<SpriteVisual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IContainerVisual, Windows::UI::Composition::ISpriteVisual2, Windows::UI::Composition::IVisual, Windows::UI::Composition::IVisual2>
{
    SpriteVisual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StepEasingFunction :
    Windows::UI::Composition::IStepEasingFunction,
    impl::base<StepEasingFunction, Windows::UI::Composition::CompositionEasingFunction, Windows::UI::Composition::CompositionObject>,
    impl::require<StepEasingFunction, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionEasingFunction, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    StepEasingFunction(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Vector2KeyFrameAnimation :
    Windows::UI::Composition::IVector2KeyFrameAnimation,
    impl::base<Vector2KeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<Vector2KeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    Vector2KeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Vector2NaturalMotionAnimation :
    Windows::UI::Composition::IVector2NaturalMotionAnimation,
    impl::base<Vector2NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<Vector2NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation>
{
    Vector2NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Vector3KeyFrameAnimation :
    Windows::UI::Composition::IVector3KeyFrameAnimation,
    impl::base<Vector3KeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<Vector3KeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    Vector3KeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Vector3NaturalMotionAnimation :
    Windows::UI::Composition::IVector3NaturalMotionAnimation,
    impl::base<Vector3NaturalMotionAnimation, Windows::UI::Composition::NaturalMotionAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<Vector3NaturalMotionAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::INaturalMotionAnimation>
{
    Vector3NaturalMotionAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Vector4KeyFrameAnimation :
    Windows::UI::Composition::IVector4KeyFrameAnimation,
    impl::base<Vector4KeyFrameAnimation, Windows::UI::Composition::KeyFrameAnimation, Windows::UI::Composition::CompositionAnimation, Windows::UI::Composition::CompositionObject>,
    impl::require<Vector4KeyFrameAnimation, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionAnimation, Windows::UI::Composition::ICompositionAnimation2, Windows::UI::Composition::ICompositionAnimation3, Windows::UI::Composition::ICompositionAnimation4, Windows::UI::Composition::ICompositionAnimationBase, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IKeyFrameAnimation, Windows::UI::Composition::IKeyFrameAnimation2, Windows::UI::Composition::IKeyFrameAnimation3>
{
    Vector4KeyFrameAnimation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Visual :
    Windows::UI::Composition::IVisual,
    impl::base<Visual, Windows::UI::Composition::CompositionObject>,
    impl::require<Visual, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::IVisual2>
{
    Visual(std::nullptr_t) noexcept {}
};

struct WINRT_EBO VisualCollection :
    Windows::UI::Composition::IVisualCollection,
    impl::base<VisualCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<VisualCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    VisualCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO VisualUnorderedCollection :
    Windows::UI::Composition::IVisualUnorderedCollection,
    impl::base<VisualUnorderedCollection, Windows::UI::Composition::CompositionObject>,
    impl::require<VisualUnorderedCollection, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4>
{
    VisualUnorderedCollection(std::nullptr_t) noexcept {}
};

}
