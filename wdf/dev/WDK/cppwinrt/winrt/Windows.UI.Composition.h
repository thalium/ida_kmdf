// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.Effects.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_IAmbientLight<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAmbientLight)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAmbientLight<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAmbientLight)->put_Color(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IAmbientLight2<D>::Intensity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAmbientLight2)->get_Intensity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAmbientLight2<D>::Intensity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAmbientLight2)->put_Intensity(value));
}

template <typename D> float consume_Windows_UI_Composition_IAnimationController<D>::PlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->get_PlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAnimationController<D>::PlaybackRate(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->put_PlaybackRate(value));
}

template <typename D> float consume_Windows_UI_Composition_IAnimationController<D>::Progress() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->get_Progress(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAnimationController<D>::Progress(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->put_Progress(value));
}

template <typename D> Windows::UI::Composition::AnimationControllerProgressBehavior consume_Windows_UI_Composition_IAnimationController<D>::ProgressBehavior() const
{
    Windows::UI::Composition::AnimationControllerProgressBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->get_ProgressBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAnimationController<D>::ProgressBehavior(Windows::UI::Composition::AnimationControllerProgressBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->put_ProgressBehavior(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IAnimationController<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->Pause());
}

template <typename D> void consume_Windows_UI_Composition_IAnimationController<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationController)->Resume());
}

template <typename D> float consume_Windows_UI_Composition_IAnimationControllerStatics<D>::MaxPlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationControllerStatics)->get_MaxPlaybackRate(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_IAnimationControllerStatics<D>::MinPlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationControllerStatics)->get_MinPlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAnimationObject<D>::PopulatePropertyInfo(param::hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& propertyInfo) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationObject)->PopulatePropertyInfo(get_abi(propertyName), get_abi(propertyInfo)));
}

template <typename D> Windows::UI::Composition::AnimationPropertyAccessMode consume_Windows_UI_Composition_IAnimationPropertyInfo<D>::AccessMode() const
{
    Windows::UI::Composition::AnimationPropertyAccessMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationPropertyInfo)->get_AccessMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IAnimationPropertyInfo<D>::AccessMode(Windows::UI::Composition::AnimationPropertyAccessMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IAnimationPropertyInfo)->put_AccessMode(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IBooleanKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBooleanKeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceScalarNaturalMotionAnimation<D>::Acceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceScalarNaturalMotionAnimation)->get_Acceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceScalarNaturalMotionAnimation<D>::Acceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceScalarNaturalMotionAnimation)->put_Acceleration(value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceScalarNaturalMotionAnimation<D>::Restitution() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceScalarNaturalMotionAnimation)->get_Restitution(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceScalarNaturalMotionAnimation<D>::Restitution(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceScalarNaturalMotionAnimation)->put_Restitution(value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceVector2NaturalMotionAnimation<D>::Acceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector2NaturalMotionAnimation)->get_Acceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceVector2NaturalMotionAnimation<D>::Acceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector2NaturalMotionAnimation)->put_Acceleration(value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceVector2NaturalMotionAnimation<D>::Restitution() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector2NaturalMotionAnimation)->get_Restitution(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceVector2NaturalMotionAnimation<D>::Restitution(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector2NaturalMotionAnimation)->put_Restitution(value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceVector3NaturalMotionAnimation<D>::Acceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector3NaturalMotionAnimation)->get_Acceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceVector3NaturalMotionAnimation<D>::Acceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector3NaturalMotionAnimation)->put_Acceleration(value));
}

template <typename D> float consume_Windows_UI_Composition_IBounceVector3NaturalMotionAnimation<D>::Restitution() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector3NaturalMotionAnimation)->get_Restitution(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IBounceVector3NaturalMotionAnimation<D>::Restitution(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IBounceVector3NaturalMotionAnimation)->put_Restitution(value));
}

template <typename D> Windows::UI::Composition::CompositionColorSpace consume_Windows_UI_Composition_IColorKeyFrameAnimation<D>::InterpolationColorSpace() const
{
    Windows::UI::Composition::CompositionColorSpace value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IColorKeyFrameAnimation)->get_InterpolationColorSpace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IColorKeyFrameAnimation<D>::InterpolationColorSpace(Windows::UI::Composition::CompositionColorSpace const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IColorKeyFrameAnimation)->put_InterpolationColorSpace(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IColorKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IColorKeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IColorKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::UI::Color const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IColorKeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::ClearAllParameters() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->ClearAllParameters());
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::ClearParameter(param::hstring const& key) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->ClearParameter(get_abi(key)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetColorParameter(param::hstring const& key, Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetColorParameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetMatrix3x2Parameter(param::hstring const& key, Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetMatrix3x2Parameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetMatrix4x4Parameter(param::hstring const& key, Windows::Foundation::Numerics::float4x4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetMatrix4x4Parameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetQuaternionParameter(param::hstring const& key, Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetQuaternionParameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetReferenceParameter(param::hstring const& key, Windows::UI::Composition::CompositionObject const& compositionObject) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetReferenceParameter(get_abi(key), get_abi(compositionObject)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetScalarParameter(param::hstring const& key, float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetScalarParameter(get_abi(key), value));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetVector2Parameter(param::hstring const& key, Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetVector2Parameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetVector3Parameter(param::hstring const& key, Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetVector3Parameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation<D>::SetVector4Parameter(param::hstring const& key, Windows::Foundation::Numerics::float4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation)->SetVector4Parameter(get_abi(key), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation2<D>::SetBooleanParameter(param::hstring const& key, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation2)->SetBooleanParameter(get_abi(key), value));
}

template <typename D> hstring consume_Windows_UI_Composition_ICompositionAnimation2<D>::Target() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation2)->get_Target(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation2<D>::Target(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation2)->put_Target(get_abi(value)));
}

template <typename D> Windows::UI::Composition::InitialValueExpressionCollection consume_Windows_UI_Composition_ICompositionAnimation3<D>::InitialValueExpressions() const
{
    Windows::UI::Composition::InitialValueExpressionCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation3)->get_InitialValueExpressions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimation4<D>::SetExpressionReferenceParameter(param::hstring const& parameterName, Windows::UI::Composition::IAnimationObject const& source) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimation4)->SetExpressionReferenceParameter(get_abi(parameterName), get_abi(source)));
}

template <typename D> int32_t consume_Windows_UI_Composition_ICompositionAnimationGroup<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimationGroup)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimationGroup<D>::Add(Windows::UI::Composition::CompositionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimationGroup)->Add(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimationGroup<D>::Remove(Windows::UI::Composition::CompositionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimationGroup)->Remove(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionAnimationGroup<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionAnimationGroup)->RemoveAll());
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionCapabilities<D>::AreEffectsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCapabilities)->AreEffectsSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionCapabilities<D>::AreEffectsFast() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCapabilities)->AreEffectsFast(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Composition_ICompositionCapabilities<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionCapabilities, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCapabilities)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Composition_ICompositionCapabilities<D>::Changed_revoker consume_Windows_UI_Composition_ICompositionCapabilities<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionCapabilities, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionCapabilities<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Composition::ICompositionCapabilities)->remove_Changed(get_abi(token)));
}

template <typename D> Windows::UI::Composition::CompositionCapabilities consume_Windows_UI_Composition_ICompositionCapabilitiesStatics<D>::GetForCurrentView() const
{
    Windows::UI::Composition::CompositionCapabilities current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCapabilitiesStatics)->GetForCurrentView(put_abi(current)));
    return current;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionClip2<D>::AnchorPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_AnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::AnchorPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_AnchorPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionClip2<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::CenterPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionClip2<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionClip2<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionClip2<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionClip2<D>::Scale() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::Scale(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Composition_ICompositionClip2<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionClip2<D>::TransformMatrix(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionClip2)->put_TransformMatrix(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_ICompositionColorBrush<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorBrush)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionColorBrush<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorBrush)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_ICompositionColorGradientStop<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorGradientStop)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionColorGradientStop<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorGradientStop)->put_Color(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionColorGradientStop<D>::Offset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorGradientStop)->get_Offset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionColorGradientStop<D>::Offset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionColorGradientStop)->put_Offset(value));
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionCommitBatch<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCommitBatch)->get_IsActive(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionCommitBatch<D>::IsEnded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCommitBatch)->get_IsEnded(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Composition_ICompositionCommitBatch<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionCommitBatch)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Composition_ICompositionCommitBatch<D>::Completed_revoker consume_Windows_UI_Composition_ICompositionCommitBatch<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionCommitBatch<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Composition::ICompositionCommitBatch)->remove_Completed(get_abi(token)));
}

template <typename D> Windows::UI::Composition::CompositionShapeCollection consume_Windows_UI_Composition_ICompositionContainerShape<D>::Shapes() const
{
    Windows::UI::Composition::CompositionShapeCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionContainerShape)->get_Shapes(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXAlphaMode consume_Windows_UI_Composition_ICompositionDrawingSurface<D>::AlphaMode() const
{
    Windows::Graphics::DirectX::DirectXAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface)->get_AlphaMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_UI_Composition_ICompositionDrawingSurface<D>::PixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface)->get_PixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Composition_ICompositionDrawingSurface<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::SizeInt32() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->get_SizeInt32(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::Resize(Windows::Graphics::SizeInt32 const& sizePixels) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->Resize(get_abi(sizePixels)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::Scroll(Windows::Graphics::PointInt32 const& offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->Scroll(get_abi(offset)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::Scroll(Windows::Graphics::PointInt32 const& offset, Windows::Graphics::RectInt32 const& scrollRect) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->ScrollRect(get_abi(offset), get_abi(scrollRect)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::ScrollWithClip(Windows::Graphics::PointInt32 const& offset, Windows::Graphics::RectInt32 const& clipRect) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->ScrollWithClip(get_abi(offset), get_abi(clipRect)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionDrawingSurface2<D>::ScrollWithClip(Windows::Graphics::PointInt32 const& offset, Windows::Graphics::RectInt32 const& clipRect, Windows::Graphics::RectInt32 const& scrollRect) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionDrawingSurface2)->ScrollRectWithClip(get_abi(offset), get_abi(clipRect), get_abi(scrollRect)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionEffectBrush<D>::GetSourceParameter(param::hstring const& name) const
{
    Windows::UI::Composition::CompositionBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectBrush)->GetSourceParameter(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionEffectBrush<D>::SetSourceParameter(param::hstring const& name, Windows::UI::Composition::CompositionBrush const& source) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectBrush)->SetSourceParameter(get_abi(name), get_abi(source)));
}

template <typename D> Windows::UI::Composition::CompositionEffectBrush consume_Windows_UI_Composition_ICompositionEffectFactory<D>::CreateBrush() const
{
    Windows::UI::Composition::CompositionEffectBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectFactory)->CreateBrush(put_abi(result)));
    return result;
}

template <typename D> winrt::hresult consume_Windows_UI_Composition_ICompositionEffectFactory<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectFactory)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionEffectFactoryLoadStatus consume_Windows_UI_Composition_ICompositionEffectFactory<D>::LoadStatus() const
{
    Windows::UI::Composition::CompositionEffectFactoryLoadStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectFactory)->get_LoadStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Composition_ICompositionEffectSourceParameter<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectSourceParameter)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionEffectSourceParameter consume_Windows_UI_Composition_ICompositionEffectSourceParameterFactory<D>::Create(param::hstring const& name) const
{
    Windows::UI::Composition::CompositionEffectSourceParameter instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEffectSourceParameterFactory)->Create(get_abi(name), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionEllipseGeometry<D>::Center() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEllipseGeometry)->get_Center(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionEllipseGeometry<D>::Center(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEllipseGeometry)->put_Center(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionEllipseGeometry<D>::Radius() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEllipseGeometry)->get_Radius(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionEllipseGeometry<D>::Radius(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionEllipseGeometry)->put_Radius(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionGeometry consume_Windows_UI_Composition_ICompositionGeometricClip<D>::Geometry() const
{
    Windows::UI::Composition::CompositionGeometry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometricClip)->get_Geometry(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGeometricClip<D>::Geometry(Windows::UI::Composition::CompositionGeometry const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometricClip)->put_Geometry(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionViewBox consume_Windows_UI_Composition_ICompositionGeometricClip<D>::ViewBox() const
{
    Windows::UI::Composition::CompositionViewBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometricClip)->get_ViewBox(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGeometricClip<D>::ViewBox(Windows::UI::Composition::CompositionViewBox const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometricClip)->put_ViewBox(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimEnd() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->get_TrimEnd(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimEnd(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->put_TrimEnd(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimOffset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->get_TrimOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimOffset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->put_TrimOffset(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimStart() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->get_TrimStart(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGeometry<D>::TrimStart(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGeometry)->put_TrimStart(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionGradientBrush<D>::AnchorPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_AnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::AnchorPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_AnchorPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionGradientBrush<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::CenterPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionColorGradientStopCollection consume_Windows_UI_Composition_ICompositionGradientBrush<D>::ColorStops() const
{
    Windows::UI::Composition::CompositionColorGradientStopCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_ColorStops(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionGradientExtendMode consume_Windows_UI_Composition_ICompositionGradientBrush<D>::ExtendMode() const
{
    Windows::UI::Composition::CompositionGradientExtendMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_ExtendMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::ExtendMode(Windows::UI::Composition::CompositionGradientExtendMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_ExtendMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionColorSpace consume_Windows_UI_Composition_ICompositionGradientBrush<D>::InterpolationSpace() const
{
    Windows::UI::Composition::CompositionColorSpace value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_InterpolationSpace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::InterpolationSpace(Windows::UI::Composition::CompositionColorSpace const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_InterpolationSpace(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionGradientBrush<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionGradientBrush<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionGradientBrush<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionGradientBrush<D>::Scale() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::Scale(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Composition_ICompositionGradientBrush<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush<D>::TransformMatrix(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush)->put_TransformMatrix(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionMappingMode consume_Windows_UI_Composition_ICompositionGradientBrush2<D>::MappingMode() const
{
    Windows::UI::Composition::CompositionMappingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush2)->get_MappingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGradientBrush2<D>::MappingMode(Windows::UI::Composition::CompositionMappingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGradientBrush2)->put_MappingMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionDrawingSurface consume_Windows_UI_Composition_ICompositionGraphicsDevice<D>::CreateDrawingSurface(Windows::Foundation::Size const& sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode const& alphaMode) const
{
    Windows::UI::Composition::CompositionDrawingSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice)->CreateDrawingSurface(get_abi(sizePixels), get_abi(pixelFormat), get_abi(alphaMode), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Composition_ICompositionGraphicsDevice<D>::RenderingDeviceReplaced(Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionGraphicsDevice, Windows::UI::Composition::RenderingDeviceReplacedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice)->add_RenderingDeviceReplaced(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Composition_ICompositionGraphicsDevice<D>::RenderingDeviceReplaced_revoker consume_Windows_UI_Composition_ICompositionGraphicsDevice<D>::RenderingDeviceReplaced(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionGraphicsDevice, Windows::UI::Composition::RenderingDeviceReplacedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RenderingDeviceReplaced_revoker>(this, RenderingDeviceReplaced(handler));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGraphicsDevice<D>::RenderingDeviceReplaced(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice)->remove_RenderingDeviceReplaced(get_abi(token)));
}

template <typename D> Windows::UI::Composition::CompositionDrawingSurface consume_Windows_UI_Composition_ICompositionGraphicsDevice2<D>::CreateDrawingSurface2(Windows::Graphics::SizeInt32 const& sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode const& alphaMode) const
{
    Windows::UI::Composition::CompositionDrawingSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice2)->CreateDrawingSurface2(get_abi(sizePixels), get_abi(pixelFormat), get_abi(alphaMode), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionVirtualDrawingSurface consume_Windows_UI_Composition_ICompositionGraphicsDevice2<D>::CreateVirtualDrawingSurface(Windows::Graphics::SizeInt32 const& sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode const& alphaMode) const
{
    Windows::UI::Composition::CompositionVirtualDrawingSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice2)->CreateVirtualDrawingSurface(get_abi(sizePixels), get_abi(pixelFormat), get_abi(alphaMode), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionMipmapSurface consume_Windows_UI_Composition_ICompositionGraphicsDevice3<D>::CreateMipmapSurface(Windows::Graphics::SizeInt32 const& sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode const& alphaMode) const
{
    Windows::UI::Composition::CompositionMipmapSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice3)->CreateMipmapSurface(get_abi(sizePixels), get_abi(pixelFormat), get_abi(alphaMode), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionGraphicsDevice3<D>::Trim() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionGraphicsDevice3)->Trim());
}

template <typename D> Windows::UI::Composition::VisualUnorderedCollection consume_Windows_UI_Composition_ICompositionLight<D>::Targets() const
{
    Windows::UI::Composition::VisualUnorderedCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLight)->get_Targets(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::VisualUnorderedCollection consume_Windows_UI_Composition_ICompositionLight2<D>::ExclusionsFromTargets() const
{
    Windows::UI::Composition::VisualUnorderedCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLight2)->get_ExclusionsFromTargets(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionLight3<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLight3)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionLight3<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLight3)->put_IsEnabled(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionLineGeometry<D>::Start() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLineGeometry)->get_Start(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionLineGeometry<D>::Start(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLineGeometry)->put_Start(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionLineGeometry<D>::End() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLineGeometry)->get_End(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionLineGeometry<D>::End(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLineGeometry)->put_End(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionLinearGradientBrush<D>::EndPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLinearGradientBrush)->get_EndPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionLinearGradientBrush<D>::EndPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLinearGradientBrush)->put_EndPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionLinearGradientBrush<D>::StartPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLinearGradientBrush)->get_StartPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionLinearGradientBrush<D>::StartPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionLinearGradientBrush)->put_StartPoint(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionMaskBrush<D>::Mask() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMaskBrush)->get_Mask(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionMaskBrush<D>::Mask(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMaskBrush)->put_Mask(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionMaskBrush<D>::Source() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMaskBrush)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionMaskBrush<D>::Source(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMaskBrush)->put_Source(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_UI_Composition_ICompositionMipmapSurface<D>::LevelCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMipmapSurface)->get_LevelCount(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXAlphaMode consume_Windows_UI_Composition_ICompositionMipmapSurface<D>::AlphaMode() const
{
    Windows::Graphics::DirectX::DirectXAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMipmapSurface)->get_AlphaMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_UI_Composition_ICompositionMipmapSurface<D>::PixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMipmapSurface)->get_PixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_UI_Composition_ICompositionMipmapSurface<D>::SizeInt32() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMipmapSurface)->get_SizeInt32(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionDrawingSurface consume_Windows_UI_Composition_ICompositionMipmapSurface<D>::GetDrawingSurfaceForLevel(uint32_t level) const
{
    Windows::UI::Composition::CompositionDrawingSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionMipmapSurface)->GetDrawingSurfaceForLevel(level, put_abi(result)));
    return result;
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::BottomInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_BottomInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::BottomInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_BottomInset(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::BottomInsetScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_BottomInsetScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::BottomInsetScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_BottomInsetScale(value));
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::IsCenterHollow() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_IsCenterHollow(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::IsCenterHollow(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_IsCenterHollow(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::LeftInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_LeftInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::LeftInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_LeftInset(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::LeftInsetScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_LeftInsetScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::LeftInsetScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_LeftInsetScale(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::RightInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_RightInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::RightInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_RightInset(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::RightInsetScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_RightInsetScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::RightInsetScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_RightInsetScale(value));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::Source() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::Source(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_Source(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::TopInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_TopInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::TopInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_TopInset(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::TopInsetScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->get_TopInsetScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::TopInsetScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->put_TopInsetScale(value));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::SetInsets(float inset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->SetInsets(inset));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::SetInsets(float left, float top, float right, float bottom) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->SetInsetsWithValues(left, top, right, bottom));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::SetInsetScales(float scale) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->SetInsetScales(scale));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionNineGridBrush<D>::SetInsetScales(float left, float top, float right, float bottom) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionNineGridBrush)->SetInsetScalesWithValues(left, top, right, bottom));
}

template <typename D> Windows::UI::Composition::Compositor consume_Windows_UI_Composition_ICompositionObject<D>::Compositor() const
{
    Windows::UI::Composition::Compositor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject)->get_Compositor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Composition_ICompositionObject<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionPropertySet consume_Windows_UI_Composition_ICompositionObject<D>::Properties() const
{
    Windows::UI::Composition::CompositionPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject<D>::StartAnimation(param::hstring const& propertyName, Windows::UI::Composition::CompositionAnimation const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject)->StartAnimation(get_abi(propertyName), get_abi(animation)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject<D>::StopAnimation(param::hstring const& propertyName) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject)->StopAnimation(get_abi(propertyName)));
}

template <typename D> hstring consume_Windows_UI_Composition_ICompositionObject2<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject2<D>::Comment(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->put_Comment(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ImplicitAnimationCollection consume_Windows_UI_Composition_ICompositionObject2<D>::ImplicitAnimations() const
{
    Windows::UI::Composition::ImplicitAnimationCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->get_ImplicitAnimations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject2<D>::ImplicitAnimations(Windows::UI::Composition::ImplicitAnimationCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->put_ImplicitAnimations(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject2<D>::StartAnimationGroup(Windows::UI::Composition::ICompositionAnimationBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->StartAnimationGroup(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObject2<D>::StopAnimationGroup(Windows::UI::Composition::ICompositionAnimationBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject2)->StopAnimationGroup(get_abi(value)));
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_UI_Composition_ICompositionObject3<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject3)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::AnimationController consume_Windows_UI_Composition_ICompositionObject4<D>::TryGetAnimationController(param::hstring const& propertyName) const
{
    Windows::UI::Composition::AnimationController result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObject4)->TryGetAnimationController(get_abi(propertyName), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObjectStatics<D>::StartAnimationWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, param::hstring const& propertyName, Windows::UI::Composition::CompositionAnimation const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObjectStatics)->StartAnimationWithIAnimationObject(get_abi(target), get_abi(propertyName), get_abi(animation)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionObjectStatics<D>::StartAnimationGroupWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionObjectStatics)->StartAnimationGroupWithIAnimationObject(get_abi(target), get_abi(animation)));
}

template <typename D> Windows::UI::Composition::CompositionPath consume_Windows_UI_Composition_ICompositionPathFactory<D>::Create(Windows::Graphics::IGeometrySource2D const& source) const
{
    Windows::UI::Composition::CompositionPath result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPathFactory)->Create(get_abi(source), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionPath consume_Windows_UI_Composition_ICompositionPathGeometry<D>::Path() const
{
    Windows::UI::Composition::CompositionPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPathGeometry)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPathGeometry<D>::Path(Windows::UI::Composition::CompositionPath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPathGeometry)->put_Path(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::BlurRadiusMultiplier() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_BlurRadiusMultiplier(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::BlurRadiusMultiplier(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->put_BlurRadiusMultiplier(value));
}

template <typename D> Windows::UI::Composition::CompositionProjectedShadowCasterCollection consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::Casters() const
{
    Windows::UI::Composition::CompositionProjectedShadowCasterCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_Casters(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionLight consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::LightSource() const
{
    Windows::UI::Composition::CompositionLight value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_LightSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::LightSource(Windows::UI::Composition::CompositionLight const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->put_LightSource(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::MaxBlurRadius() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_MaxBlurRadius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::MaxBlurRadius(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->put_MaxBlurRadius(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::MinBlurRadius() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_MinBlurRadius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::MinBlurRadius(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->put_MinBlurRadius(value));
}

template <typename D> Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection consume_Windows_UI_Composition_ICompositionProjectedShadow<D>::Receivers() const
{
    Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadow)->get_Receivers(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionProjectedShadowCaster<D>::Brush() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCaster)->get_Brush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCaster<D>::Brush(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCaster)->put_Brush(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_ICompositionProjectedShadowCaster<D>::CastingVisual() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCaster)->get_CastingVisual(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCaster<D>::CastingVisual(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCaster)->put_CastingVisual(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::InsertAbove(Windows::UI::Composition::CompositionProjectedShadowCaster const& newCaster, Windows::UI::Composition::CompositionProjectedShadowCaster const& reference) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->InsertAbove(get_abi(newCaster), get_abi(reference)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::InsertAtBottom(Windows::UI::Composition::CompositionProjectedShadowCaster const& newCaster) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->InsertAtBottom(get_abi(newCaster)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::InsertAtTop(Windows::UI::Composition::CompositionProjectedShadowCaster const& newCaster) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->InsertAtTop(get_abi(newCaster)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::InsertBelow(Windows::UI::Composition::CompositionProjectedShadowCaster const& newCaster, Windows::UI::Composition::CompositionProjectedShadowCaster const& reference) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->InsertBelow(get_abi(newCaster), get_abi(reference)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::Remove(Windows::UI::Composition::CompositionProjectedShadowCaster const& caster) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->Remove(get_abi(caster)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollection<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollection)->RemoveAll());
}

template <typename D> int32_t consume_Windows_UI_Composition_ICompositionProjectedShadowCasterCollectionStatics<D>::MaxRespectedCasters() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics)->get_MaxRespectedCasters(&value));
    return value;
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_ICompositionProjectedShadowReceiver<D>::ReceivingVisual() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiver)->get_ReceivingVisual(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowReceiver<D>::ReceivingVisual(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiver)->put_ReceivingVisual(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowReceiverUnorderedCollection<D>::Add(Windows::UI::Composition::CompositionProjectedShadowReceiver const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection)->Add(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Composition_ICompositionProjectedShadowReceiverUnorderedCollection<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowReceiverUnorderedCollection<D>::Remove(Windows::UI::Composition::CompositionProjectedShadowReceiver const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection)->Remove(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionProjectedShadowReceiverUnorderedCollection<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection)->RemoveAll());
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertColor(param::hstring const& propertyName, Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertColor(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertMatrix3x2(param::hstring const& propertyName, Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertMatrix3x2(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertMatrix4x4(param::hstring const& propertyName, Windows::Foundation::Numerics::float4x4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertMatrix4x4(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertQuaternion(param::hstring const& propertyName, Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertQuaternion(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertScalar(param::hstring const& propertyName, float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertScalar(get_abi(propertyName), value));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertVector2(param::hstring const& propertyName, Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertVector2(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertVector3(param::hstring const& propertyName, Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertVector3(get_abi(propertyName), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet<D>::InsertVector4(param::hstring const& propertyName, Windows::Foundation::Numerics::float4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->InsertVector4(get_abi(propertyName), get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetColor(param::hstring const& propertyName, Windows::UI::Color& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetColor(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetMatrix3x2(param::hstring const& propertyName, Windows::Foundation::Numerics::float3x2& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetMatrix3x2(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetMatrix4x4(param::hstring const& propertyName, Windows::Foundation::Numerics::float4x4& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetMatrix4x4(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetQuaternion(param::hstring const& propertyName, Windows::Foundation::Numerics::quaternion& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetQuaternion(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetScalar(param::hstring const& propertyName, float& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetScalar(get_abi(propertyName), &value, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetVector2(param::hstring const& propertyName, Windows::Foundation::Numerics::float2& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetVector2(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetVector3(param::hstring const& propertyName, Windows::Foundation::Numerics::float3& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetVector3(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet<D>::TryGetVector4(param::hstring const& propertyName, Windows::Foundation::Numerics::float4& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet)->TryGetVector4(get_abi(propertyName), put_abi(value), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionPropertySet2<D>::InsertBoolean(param::hstring const& propertyName, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet2)->InsertBoolean(get_abi(propertyName), value));
}

template <typename D> Windows::UI::Composition::CompositionGetValueStatus consume_Windows_UI_Composition_ICompositionPropertySet2<D>::TryGetBoolean(param::hstring const& propertyName, bool& value) const
{
    Windows::UI::Composition::CompositionGetValueStatus result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionPropertySet2)->TryGetBoolean(get_abi(propertyName), &value, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::EllipseCenter() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->get_EllipseCenter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::EllipseCenter(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->put_EllipseCenter(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::EllipseRadius() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->get_EllipseRadius(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::EllipseRadius(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->put_EllipseRadius(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::GradientOriginOffset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->get_GradientOriginOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRadialGradientBrush<D>::GradientOriginOffset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRadialGradientBrush)->put_GradientOriginOffset(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRectangleGeometry<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRectangleGeometry)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRectangleGeometry<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRectangleGeometry)->put_Offset(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRectangleGeometry<D>::Size() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRectangleGeometry)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRectangleGeometry<D>::Size(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRectangleGeometry)->put_Size(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::CornerRadius() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->get_CornerRadius(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::CornerRadius(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->put_CornerRadius(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->put_Offset(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::Size() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionRoundedRectangleGeometry<D>::Size(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionRoundedRectangleGeometry)->put_Size(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionScopedBatch<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->get_IsActive(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionScopedBatch<D>::IsEnded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->get_IsEnded(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionScopedBatch<D>::End() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->End());
}

template <typename D> void consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->Resume());
}

template <typename D> void consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Suspend() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->Suspend());
}

template <typename D> winrt::event_token consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Completed_revoker consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionScopedBatch<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Composition::ICompositionScopedBatch)->remove_Completed(get_abi(token)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionShape<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::CenterPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionShape<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionShape<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionShape<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionShape<D>::Scale() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::Scale(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Composition_ICompositionShape<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionShape<D>::TransformMatrix(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionShape)->put_TransformMatrix(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionSpriteShape<D>::FillBrush() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_FillBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::FillBrush(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_FillBrush(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionGeometry consume_Windows_UI_Composition_ICompositionSpriteShape<D>::Geometry() const
{
    Windows::UI::Composition::CompositionGeometry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_Geometry(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::Geometry(Windows::UI::Composition::CompositionGeometry const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_Geometry(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionSpriteShape<D>::IsStrokeNonScaling() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_IsStrokeNonScaling(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::IsStrokeNonScaling(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_IsStrokeNonScaling(value));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeBrush() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeBrush(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeBrush(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionStrokeDashArray consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeDashArray() const
{
    Windows::UI::Composition::CompositionStrokeDashArray value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeDashArray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionStrokeCap consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeDashCap() const
{
    Windows::UI::Composition::CompositionStrokeCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeDashCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeDashCap(Windows::UI::Composition::CompositionStrokeCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeDashCap(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeDashOffset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeDashOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeDashOffset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeDashOffset(value));
}

template <typename D> Windows::UI::Composition::CompositionStrokeCap consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeEndCap() const
{
    Windows::UI::Composition::CompositionStrokeCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeEndCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeEndCap(Windows::UI::Composition::CompositionStrokeCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeEndCap(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionStrokeLineJoin consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeLineJoin() const
{
    Windows::UI::Composition::CompositionStrokeLineJoin value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeLineJoin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeLineJoin(Windows::UI::Composition::CompositionStrokeLineJoin const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeLineJoin(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeMiterLimit() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeMiterLimit(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeMiterLimit(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeMiterLimit(value));
}

template <typename D> Windows::UI::Composition::CompositionStrokeCap consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeStartCap() const
{
    Windows::UI::Composition::CompositionStrokeCap value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeStartCap(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeStartCap(Windows::UI::Composition::CompositionStrokeCap const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeStartCap(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeThickness() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->get_StrokeThickness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSpriteShape<D>::StrokeThickness(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSpriteShape)->put_StrokeThickness(value));
}

template <typename D> Windows::UI::Composition::CompositionBitmapInterpolationMode consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::BitmapInterpolationMode() const
{
    Windows::UI::Composition::CompositionBitmapInterpolationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->get_BitmapInterpolationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::BitmapInterpolationMode(Windows::UI::Composition::CompositionBitmapInterpolationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->put_BitmapInterpolationMode(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::HorizontalAlignmentRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->get_HorizontalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::HorizontalAlignmentRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->put_HorizontalAlignmentRatio(value));
}

template <typename D> Windows::UI::Composition::CompositionStretch consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::Stretch() const
{
    Windows::UI::Composition::CompositionStretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->get_Stretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::Stretch(Windows::UI::Composition::CompositionStretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->put_Stretch(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ICompositionSurface consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::Surface() const
{
    Windows::UI::Composition::ICompositionSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->get_Surface(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::Surface(Windows::UI::Composition::ICompositionSurface const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->put_Surface(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::VerticalAlignmentRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->get_VerticalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush<D>::VerticalAlignmentRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush)->put_VerticalAlignmentRatio(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::AnchorPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_AnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::AnchorPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_AnchorPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::CenterPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::Scale() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::Scale(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush2<D>::TransformMatrix(Windows::Foundation::Numerics::float3x2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush2)->put_TransformMatrix(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Composition_ICompositionSurfaceBrush3<D>::SnapToPixels() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush3)->get_SnapToPixels(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionSurfaceBrush3<D>::SnapToPixels(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionSurfaceBrush3)->put_SnapToPixels(value));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_ICompositionTarget<D>::Root() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionTarget)->get_Root(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionTarget<D>::Root(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionTarget)->put_Root(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionViewBox<D>::HorizontalAlignmentRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->get_HorizontalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionViewBox<D>::HorizontalAlignmentRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->put_HorizontalAlignmentRatio(value));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionViewBox<D>::Offset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionViewBox<D>::Offset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->put_Offset(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionViewBox<D>::Size() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionViewBox<D>::Size(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->put_Size(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionStretch consume_Windows_UI_Composition_ICompositionViewBox<D>::Stretch() const
{
    Windows::UI::Composition::CompositionStretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->get_Stretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionViewBox<D>::Stretch(Windows::UI::Composition::CompositionStretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->put_Stretch(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositionViewBox<D>::VerticalAlignmentRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->get_VerticalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionViewBox<D>::VerticalAlignmentRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionViewBox)->put_VerticalAlignmentRatio(value));
}

template <typename D> void consume_Windows_UI_Composition_ICompositionVirtualDrawingSurface<D>::Trim(array_view<Windows::Graphics::RectInt32 const> rects) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVirtualDrawingSurface)->Trim(rects.size(), get_abi(rects)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceVisual() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->get_SourceVisual(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceVisual(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->put_SourceVisual(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceOffset() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->get_SourceOffset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceOffset(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->put_SourceOffset(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceSize() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->get_SourceSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositionVisualSurface<D>::SourceSize(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositionVisualSurface)->put_SourceSize(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ColorKeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateColorKeyFrameAnimation() const
{
    Windows::UI::Composition::ColorKeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateColorKeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionColorBrush consume_Windows_UI_Composition_ICompositor<D>::CreateColorBrush() const
{
    Windows::UI::Composition::CompositionColorBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateColorBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionColorBrush consume_Windows_UI_Composition_ICompositor<D>::CreateColorBrush(Windows::UI::Color const& color) const
{
    Windows::UI::Composition::CompositionColorBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateColorBrushWithColor(get_abi(color), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ContainerVisual consume_Windows_UI_Composition_ICompositor<D>::CreateContainerVisual() const
{
    Windows::UI::Composition::ContainerVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateContainerVisual(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CubicBezierEasingFunction consume_Windows_UI_Composition_ICompositor<D>::CreateCubicBezierEasingFunction(Windows::Foundation::Numerics::float2 const& controlPoint1, Windows::Foundation::Numerics::float2 const& controlPoint2) const
{
    Windows::UI::Composition::CubicBezierEasingFunction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateCubicBezierEasingFunction(get_abi(controlPoint1), get_abi(controlPoint2), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionEffectFactory consume_Windows_UI_Composition_ICompositor<D>::CreateEffectFactory(Windows::Graphics::Effects::IGraphicsEffect const& graphicsEffect) const
{
    Windows::UI::Composition::CompositionEffectFactory result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateEffectFactory(get_abi(graphicsEffect), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionEffectFactory consume_Windows_UI_Composition_ICompositor<D>::CreateEffectFactory(Windows::Graphics::Effects::IGraphicsEffect const& graphicsEffect, param::iterable<hstring> const& animatableProperties) const
{
    Windows::UI::Composition::CompositionEffectFactory result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateEffectFactoryWithProperties(get_abi(graphicsEffect), get_abi(animatableProperties), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateExpressionAnimation() const
{
    Windows::UI::Composition::ExpressionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateExpressionAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateExpressionAnimation(param::hstring const& expression) const
{
    Windows::UI::Composition::ExpressionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateExpressionAnimationWithExpression(get_abi(expression), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::InsetClip consume_Windows_UI_Composition_ICompositor<D>::CreateInsetClip() const
{
    Windows::UI::Composition::InsetClip result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateInsetClip(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::InsetClip consume_Windows_UI_Composition_ICompositor<D>::CreateInsetClip(float leftInset, float topInset, float rightInset, float bottomInset) const
{
    Windows::UI::Composition::InsetClip result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateInsetClipWithInsets(leftInset, topInset, rightInset, bottomInset, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::LinearEasingFunction consume_Windows_UI_Composition_ICompositor<D>::CreateLinearEasingFunction() const
{
    Windows::UI::Composition::LinearEasingFunction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateLinearEasingFunction(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionPropertySet consume_Windows_UI_Composition_ICompositor<D>::CreatePropertySet() const
{
    Windows::UI::Composition::CompositionPropertySet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreatePropertySet(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::QuaternionKeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateQuaternionKeyFrameAnimation() const
{
    Windows::UI::Composition::QuaternionKeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateQuaternionKeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ScalarKeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateScalarKeyFrameAnimation() const
{
    Windows::UI::Composition::ScalarKeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateScalarKeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionScopedBatch consume_Windows_UI_Composition_ICompositor<D>::CreateScopedBatch(Windows::UI::Composition::CompositionBatchTypes const& batchType) const
{
    Windows::UI::Composition::CompositionScopedBatch result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateScopedBatch(get_abi(batchType), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::SpriteVisual consume_Windows_UI_Composition_ICompositor<D>::CreateSpriteVisual() const
{
    Windows::UI::Composition::SpriteVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateSpriteVisual(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionSurfaceBrush consume_Windows_UI_Composition_ICompositor<D>::CreateSurfaceBrush() const
{
    Windows::UI::Composition::CompositionSurfaceBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateSurfaceBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionSurfaceBrush consume_Windows_UI_Composition_ICompositor<D>::CreateSurfaceBrush(Windows::UI::Composition::ICompositionSurface const& surface) const
{
    Windows::UI::Composition::CompositionSurfaceBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateSurfaceBrushWithSurface(get_abi(surface), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionTarget consume_Windows_UI_Composition_ICompositor<D>::CreateTargetForCurrentView() const
{
    Windows::UI::Composition::CompositionTarget result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateTargetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Vector2KeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateVector2KeyFrameAnimation() const
{
    Windows::UI::Composition::Vector2KeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateVector2KeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Vector3KeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateVector3KeyFrameAnimation() const
{
    Windows::UI::Composition::Vector3KeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateVector3KeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Vector4KeyFrameAnimation consume_Windows_UI_Composition_ICompositor<D>::CreateVector4KeyFrameAnimation() const
{
    Windows::UI::Composition::Vector4KeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->CreateVector4KeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionCommitBatch consume_Windows_UI_Composition_ICompositor<D>::GetCommitBatch(Windows::UI::Composition::CompositionBatchTypes const& batchType) const
{
    Windows::UI::Composition::CompositionCommitBatch result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor)->GetCommitBatch(get_abi(batchType), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::AmbientLight consume_Windows_UI_Composition_ICompositor2<D>::CreateAmbientLight() const
{
    Windows::UI::Composition::AmbientLight result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateAmbientLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionAnimationGroup consume_Windows_UI_Composition_ICompositor2<D>::CreateAnimationGroup() const
{
    Windows::UI::Composition::CompositionAnimationGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateAnimationGroup(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionBackdropBrush consume_Windows_UI_Composition_ICompositor2<D>::CreateBackdropBrush() const
{
    Windows::UI::Composition::CompositionBackdropBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateBackdropBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::DistantLight consume_Windows_UI_Composition_ICompositor2<D>::CreateDistantLight() const
{
    Windows::UI::Composition::DistantLight result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateDistantLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::DropShadow consume_Windows_UI_Composition_ICompositor2<D>::CreateDropShadow() const
{
    Windows::UI::Composition::DropShadow result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateDropShadow(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ImplicitAnimationCollection consume_Windows_UI_Composition_ICompositor2<D>::CreateImplicitAnimationCollection() const
{
    Windows::UI::Composition::ImplicitAnimationCollection result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateImplicitAnimationCollection(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::LayerVisual consume_Windows_UI_Composition_ICompositor2<D>::CreateLayerVisual() const
{
    Windows::UI::Composition::LayerVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateLayerVisual(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionMaskBrush consume_Windows_UI_Composition_ICompositor2<D>::CreateMaskBrush() const
{
    Windows::UI::Composition::CompositionMaskBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateMaskBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionNineGridBrush consume_Windows_UI_Composition_ICompositor2<D>::CreateNineGridBrush() const
{
    Windows::UI::Composition::CompositionNineGridBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateNineGridBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::PointLight consume_Windows_UI_Composition_ICompositor2<D>::CreatePointLight() const
{
    Windows::UI::Composition::PointLight result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreatePointLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::SpotLight consume_Windows_UI_Composition_ICompositor2<D>::CreateSpotLight() const
{
    Windows::UI::Composition::SpotLight result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateSpotLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::StepEasingFunction consume_Windows_UI_Composition_ICompositor2<D>::CreateStepEasingFunction() const
{
    Windows::UI::Composition::StepEasingFunction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateStepEasingFunction(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::StepEasingFunction consume_Windows_UI_Composition_ICompositor2<D>::CreateStepEasingFunction(int32_t stepCount) const
{
    Windows::UI::Composition::StepEasingFunction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor2)->CreateStepEasingFunctionWithStepCount(stepCount, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionBackdropBrush consume_Windows_UI_Composition_ICompositor3<D>::CreateHostBackdropBrush() const
{
    Windows::UI::Composition::CompositionBackdropBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor3)->CreateHostBackdropBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionColorGradientStop consume_Windows_UI_Composition_ICompositor4<D>::CreateColorGradientStop() const
{
    Windows::UI::Composition::CompositionColorGradientStop result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateColorGradientStop(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionColorGradientStop consume_Windows_UI_Composition_ICompositor4<D>::CreateColorGradientStop(float offset, Windows::UI::Color const& color) const
{
    Windows::UI::Composition::CompositionColorGradientStop result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateColorGradientStopWithOffsetAndColor(offset, get_abi(color), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionLinearGradientBrush consume_Windows_UI_Composition_ICompositor4<D>::CreateLinearGradientBrush() const
{
    Windows::UI::Composition::CompositionLinearGradientBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateLinearGradientBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::SpringScalarNaturalMotionAnimation consume_Windows_UI_Composition_ICompositor4<D>::CreateSpringScalarAnimation() const
{
    Windows::UI::Composition::SpringScalarNaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateSpringScalarAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::SpringVector2NaturalMotionAnimation consume_Windows_UI_Composition_ICompositor4<D>::CreateSpringVector2Animation() const
{
    Windows::UI::Composition::SpringVector2NaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateSpringVector2Animation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::SpringVector3NaturalMotionAnimation consume_Windows_UI_Composition_ICompositor4<D>::CreateSpringVector3Animation() const
{
    Windows::UI::Composition::SpringVector3NaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor4)->CreateSpringVector3Animation(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Composition_ICompositor5<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositor5<D>::Comment(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->put_Comment(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ICompositor5<D>::GlobalPlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->get_GlobalPlaybackRate(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ICompositor5<D>::GlobalPlaybackRate(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->put_GlobalPlaybackRate(value));
}

template <typename D> Windows::UI::Composition::BounceScalarNaturalMotionAnimation consume_Windows_UI_Composition_ICompositor5<D>::CreateBounceScalarAnimation() const
{
    Windows::UI::Composition::BounceScalarNaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateBounceScalarAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::BounceVector2NaturalMotionAnimation consume_Windows_UI_Composition_ICompositor5<D>::CreateBounceVector2Animation() const
{
    Windows::UI::Composition::BounceVector2NaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateBounceVector2Animation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::BounceVector3NaturalMotionAnimation consume_Windows_UI_Composition_ICompositor5<D>::CreateBounceVector3Animation() const
{
    Windows::UI::Composition::BounceVector3NaturalMotionAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateBounceVector3Animation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionContainerShape consume_Windows_UI_Composition_ICompositor5<D>::CreateContainerShape() const
{
    Windows::UI::Composition::CompositionContainerShape result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateContainerShape(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionEllipseGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreateEllipseGeometry() const
{
    Windows::UI::Composition::CompositionEllipseGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateEllipseGeometry(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionLineGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreateLineGeometry() const
{
    Windows::UI::Composition::CompositionLineGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateLineGeometry(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionPathGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreatePathGeometry() const
{
    Windows::UI::Composition::CompositionPathGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreatePathGeometry(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionPathGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreatePathGeometry(Windows::UI::Composition::CompositionPath const& path) const
{
    Windows::UI::Composition::CompositionPathGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreatePathGeometryWithPath(get_abi(path), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::PathKeyFrameAnimation consume_Windows_UI_Composition_ICompositor5<D>::CreatePathKeyFrameAnimation() const
{
    Windows::UI::Composition::PathKeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreatePathKeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionRectangleGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreateRectangleGeometry() const
{
    Windows::UI::Composition::CompositionRectangleGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateRectangleGeometry(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionRoundedRectangleGeometry consume_Windows_UI_Composition_ICompositor5<D>::CreateRoundedRectangleGeometry() const
{
    Windows::UI::Composition::CompositionRoundedRectangleGeometry result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateRoundedRectangleGeometry(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ShapeVisual consume_Windows_UI_Composition_ICompositor5<D>::CreateShapeVisual() const
{
    Windows::UI::Composition::ShapeVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateShapeVisual(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionSpriteShape consume_Windows_UI_Composition_ICompositor5<D>::CreateSpriteShape() const
{
    Windows::UI::Composition::CompositionSpriteShape result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateSpriteShape(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionSpriteShape consume_Windows_UI_Composition_ICompositor5<D>::CreateSpriteShape(Windows::UI::Composition::CompositionGeometry const& geometry) const
{
    Windows::UI::Composition::CompositionSpriteShape result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateSpriteShapeWithGeometry(get_abi(geometry), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionViewBox consume_Windows_UI_Composition_ICompositor5<D>::CreateViewBox() const
{
    Windows::UI::Composition::CompositionViewBox result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->CreateViewBox(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Composition_ICompositor5<D>::RequestCommitAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor5)->RequestCommitAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::UI::Composition::CompositionGeometricClip consume_Windows_UI_Composition_ICompositor6<D>::CreateGeometricClip() const
{
    Windows::UI::Composition::CompositionGeometricClip result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor6)->CreateGeometricClip(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionGeometricClip consume_Windows_UI_Composition_ICompositor6<D>::CreateGeometricClip(Windows::UI::Composition::CompositionGeometry const& geometry) const
{
    Windows::UI::Composition::CompositionGeometricClip result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor6)->CreateGeometricClipWithGeometry(get_abi(geometry), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::RedirectVisual consume_Windows_UI_Composition_ICompositor6<D>::CreateRedirectVisual() const
{
    Windows::UI::Composition::RedirectVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor6)->CreateRedirectVisual(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::RedirectVisual consume_Windows_UI_Composition_ICompositor6<D>::CreateRedirectVisual(Windows::UI::Composition::Visual const& source) const
{
    Windows::UI::Composition::RedirectVisual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor6)->CreateRedirectVisualWithSourceVisual(get_abi(source), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::BooleanKeyFrameAnimation consume_Windows_UI_Composition_ICompositor6<D>::CreateBooleanKeyFrameAnimation() const
{
    Windows::UI::Composition::BooleanKeyFrameAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositor6)->CreateBooleanKeyFrameAnimation(put_abi(result)));
    return result;
}

template <typename D> float consume_Windows_UI_Composition_ICompositorStatics<D>::MaxGlobalPlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorStatics)->get_MaxGlobalPlaybackRate(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_ICompositorStatics<D>::MinGlobalPlaybackRate() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorStatics)->get_MinGlobalPlaybackRate(&value));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionProjectedShadowCaster consume_Windows_UI_Composition_ICompositorWithProjectedShadow<D>::CreateProjectedShadowCaster() const
{
    Windows::UI::Composition::CompositionProjectedShadowCaster result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorWithProjectedShadow)->CreateProjectedShadowCaster(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionProjectedShadow consume_Windows_UI_Composition_ICompositorWithProjectedShadow<D>::CreateProjectedShadow() const
{
    Windows::UI::Composition::CompositionProjectedShadow result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorWithProjectedShadow)->CreateProjectedShadow(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionProjectedShadowReceiver consume_Windows_UI_Composition_ICompositorWithProjectedShadow<D>::CreateProjectedShadowReceiver() const
{
    Windows::UI::Composition::CompositionProjectedShadowReceiver result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorWithProjectedShadow)->CreateProjectedShadowReceiver(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionRadialGradientBrush consume_Windows_UI_Composition_ICompositorWithRadialGradient<D>::CreateRadialGradientBrush() const
{
    Windows::UI::Composition::CompositionRadialGradientBrush result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorWithRadialGradient)->CreateRadialGradientBrush(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::CompositionVisualSurface consume_Windows_UI_Composition_ICompositorWithVisualSurface<D>::CreateVisualSurface() const
{
    Windows::UI::Composition::CompositionVisualSurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICompositorWithVisualSurface)->CreateVisualSurface(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::VisualCollection consume_Windows_UI_Composition_IContainerVisual<D>::Children() const
{
    Windows::UI::Composition::VisualCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IContainerVisual)->get_Children(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICubicBezierEasingFunction<D>::ControlPoint1() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICubicBezierEasingFunction)->get_ControlPoint1(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_ICubicBezierEasingFunction<D>::ControlPoint2() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ICubicBezierEasingFunction)->get_ControlPoint2(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_IDistantLight<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDistantLight<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_IDistantLight<D>::CoordinateSpace() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->get_CoordinateSpace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDistantLight<D>::CoordinateSpace(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->put_CoordinateSpace(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IDistantLight<D>::Direction() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDistantLight<D>::Direction(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight)->put_Direction(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IDistantLight2<D>::Intensity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight2)->get_Intensity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDistantLight2<D>::Intensity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDistantLight2)->put_Intensity(value));
}

template <typename D> float consume_Windows_UI_Composition_IDropShadow<D>::BlurRadius() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->get_BlurRadius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow<D>::BlurRadius(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->put_BlurRadius(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_IDropShadow<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->put_Color(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_IDropShadow<D>::Mask() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->get_Mask(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow<D>::Mask(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->put_Mask(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IDropShadow<D>::Offset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow<D>::Offset(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IDropShadow<D>::Opacity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow<D>::Opacity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow)->put_Opacity(value));
}

template <typename D> Windows::UI::Composition::CompositionDropShadowSourcePolicy consume_Windows_UI_Composition_IDropShadow2<D>::SourcePolicy() const
{
    Windows::UI::Composition::CompositionDropShadowSourcePolicy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow2)->get_SourcePolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IDropShadow2<D>::SourcePolicy(Windows::UI::Composition::CompositionDropShadowSourcePolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IDropShadow2)->put_SourcePolicy(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Composition_IExpressionAnimation<D>::Expression() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IExpressionAnimation)->get_Expression(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IExpressionAnimation<D>::Expression(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IExpressionAnimation)->put_Expression(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IInsetClip<D>::BottomInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->get_BottomInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IInsetClip<D>::BottomInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->put_BottomInset(value));
}

template <typename D> float consume_Windows_UI_Composition_IInsetClip<D>::LeftInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->get_LeftInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IInsetClip<D>::LeftInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->put_LeftInset(value));
}

template <typename D> float consume_Windows_UI_Composition_IInsetClip<D>::RightInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->get_RightInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IInsetClip<D>::RightInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->put_RightInset(value));
}

template <typename D> float consume_Windows_UI_Composition_IInsetClip<D>::TopInset() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->get_TopInset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IInsetClip<D>::TopInset(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IInsetClip)->put_TopInset(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_IKeyFrameAnimation<D>::DelayTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_DelayTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::DelayTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->put_DelayTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_IKeyFrameAnimation<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->put_Duration(get_abi(value)));
}

template <typename D> Windows::UI::Composition::AnimationIterationBehavior consume_Windows_UI_Composition_IKeyFrameAnimation<D>::IterationBehavior() const
{
    Windows::UI::Composition::AnimationIterationBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_IterationBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::IterationBehavior(Windows::UI::Composition::AnimationIterationBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->put_IterationBehavior(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Composition_IKeyFrameAnimation<D>::IterationCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_IterationCount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::IterationCount(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->put_IterationCount(value));
}

template <typename D> int32_t consume_Windows_UI_Composition_IKeyFrameAnimation<D>::KeyFrameCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_KeyFrameCount(&value));
    return value;
}

template <typename D> Windows::UI::Composition::AnimationStopBehavior consume_Windows_UI_Composition_IKeyFrameAnimation<D>::StopBehavior() const
{
    Windows::UI::Composition::AnimationStopBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->get_StopBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::StopBehavior(Windows::UI::Composition::AnimationStopBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->put_StopBehavior(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::InsertExpressionKeyFrame(float normalizedProgressKey, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->InsertExpressionKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation<D>::InsertExpressionKeyFrame(float normalizedProgressKey, param::hstring const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation)->InsertExpressionKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> Windows::UI::Composition::AnimationDirection consume_Windows_UI_Composition_IKeyFrameAnimation2<D>::Direction() const
{
    Windows::UI::Composition::AnimationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation2)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation2<D>::Direction(Windows::UI::Composition::AnimationDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation2)->put_Direction(get_abi(value)));
}

template <typename D> Windows::UI::Composition::AnimationDelayBehavior consume_Windows_UI_Composition_IKeyFrameAnimation3<D>::DelayBehavior() const
{
    Windows::UI::Composition::AnimationDelayBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation3)->get_DelayBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IKeyFrameAnimation3<D>::DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IKeyFrameAnimation3)->put_DelayBehavior(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionEffectBrush consume_Windows_UI_Composition_ILayerVisual<D>::Effect() const
{
    Windows::UI::Composition::CompositionEffectBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ILayerVisual)->get_Effect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ILayerVisual<D>::Effect(Windows::UI::Composition::CompositionEffectBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ILayerVisual)->put_Effect(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionShadow consume_Windows_UI_Composition_ILayerVisual2<D>::Shadow() const
{
    Windows::UI::Composition::CompositionShadow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ILayerVisual2)->get_Shadow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ILayerVisual2<D>::Shadow(Windows::UI::Composition::CompositionShadow const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ILayerVisual2)->put_Shadow(get_abi(value)));
}

template <typename D> Windows::UI::Composition::AnimationDelayBehavior consume_Windows_UI_Composition_INaturalMotionAnimation<D>::DelayBehavior() const
{
    Windows::UI::Composition::AnimationDelayBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->get_DelayBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_INaturalMotionAnimation<D>::DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->put_DelayBehavior(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_INaturalMotionAnimation<D>::DelayTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->get_DelayTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_INaturalMotionAnimation<D>::DelayTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->put_DelayTime(get_abi(value)));
}

template <typename D> Windows::UI::Composition::AnimationStopBehavior consume_Windows_UI_Composition_INaturalMotionAnimation<D>::StopBehavior() const
{
    Windows::UI::Composition::AnimationStopBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->get_StopBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_INaturalMotionAnimation<D>::StopBehavior(Windows::UI::Composition::AnimationStopBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::INaturalMotionAnimation)->put_StopBehavior(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IPathKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::UI::Composition::CompositionPath const& path) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPathKeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(path)));
}

template <typename D> void consume_Windows_UI_Composition_IPathKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::UI::Composition::CompositionPath const& path, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPathKeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(path), get_abi(easingFunction)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_IPointLight<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_Color(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight<D>::ConstantAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_ConstantAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::ConstantAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_ConstantAttenuation(value));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_IPointLight<D>::CoordinateSpace() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_CoordinateSpace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::CoordinateSpace(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_CoordinateSpace(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight<D>::LinearAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_LinearAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::LinearAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_LinearAttenuation(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IPointLight<D>::Offset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::Offset(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight<D>::QuadraticAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->get_QuadraticAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight<D>::QuadraticAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight)->put_QuadraticAttenuation(value));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight2<D>::Intensity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight2)->get_Intensity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight2<D>::Intensity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight2)->put_Intensity(value));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight3<D>::MinAttenuationCutoff() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight3)->get_MinAttenuationCutoff(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight3<D>::MinAttenuationCutoff(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight3)->put_MinAttenuationCutoff(value));
}

template <typename D> float consume_Windows_UI_Composition_IPointLight3<D>::MaxAttenuationCutoff() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight3)->get_MaxAttenuationCutoff(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IPointLight3<D>::MaxAttenuationCutoff(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IPointLight3)->put_MaxAttenuationCutoff(value));
}

template <typename D> void consume_Windows_UI_Composition_IQuaternionKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IQuaternionKeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IQuaternionKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::quaternion const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IQuaternionKeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_IRedirectVisual<D>::Source() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IRedirectVisual)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IRedirectVisual<D>::Source(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IRedirectVisual)->put_Source(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionGraphicsDevice consume_Windows_UI_Composition_IRenderingDeviceReplacedEventArgs<D>::GraphicsDevice() const
{
    Windows::UI::Composition::CompositionGraphicsDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IRenderingDeviceReplacedEventArgs)->get_GraphicsDevice(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IScalarKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarKeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, value));
}

template <typename D> void consume_Windows_UI_Composition_IScalarKeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, float value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarKeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, value, get_abi(easingFunction)));
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::FinalValue() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->get_FinalValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::FinalValue(optional<float> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->put_FinalValue(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::InitialValue() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->get_InitialValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::InitialValue(optional<float> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->put_InitialValue(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::InitialVelocity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->get_InitialVelocity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IScalarNaturalMotionAnimation<D>::InitialVelocity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IScalarNaturalMotionAnimation)->put_InitialVelocity(value));
}

template <typename D> Windows::UI::Composition::CompositionShapeCollection consume_Windows_UI_Composition_IShapeVisual<D>::Shapes() const
{
    Windows::UI::Composition::CompositionShapeCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IShapeVisual)->get_Shapes(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::CompositionViewBox consume_Windows_UI_Composition_IShapeVisual<D>::ViewBox() const
{
    Windows::UI::Composition::CompositionViewBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IShapeVisual)->get_ViewBox(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IShapeVisual<D>::ViewBox(Windows::UI::Composition::CompositionViewBox const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IShapeVisual)->put_ViewBox(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::ConstantAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_ConstantAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::ConstantAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_ConstantAttenuation(value));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_ISpotLight<D>::CoordinateSpace() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_CoordinateSpace(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::CoordinateSpace(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_CoordinateSpace(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_ISpotLight<D>::Direction() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::Direction(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_Direction(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::InnerConeAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_InnerConeAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::InnerConeAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_InnerConeAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::InnerConeAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_InnerConeAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::InnerConeAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_InnerConeAngleInDegrees(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_ISpotLight<D>::InnerConeColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_InnerConeColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::InnerConeColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_InnerConeColor(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::LinearAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_LinearAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::LinearAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_LinearAttenuation(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_ISpotLight<D>::Offset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::Offset(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::OuterConeAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_OuterConeAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::OuterConeAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_OuterConeAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::OuterConeAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_OuterConeAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::OuterConeAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_OuterConeAngleInDegrees(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Composition_ISpotLight<D>::OuterConeColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_OuterConeColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::OuterConeColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_OuterConeColor(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight<D>::QuadraticAttenuation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->get_QuadraticAttenuation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight<D>::QuadraticAttenuation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight)->put_QuadraticAttenuation(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight2<D>::InnerConeIntensity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight2)->get_InnerConeIntensity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight2<D>::InnerConeIntensity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight2)->put_InnerConeIntensity(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight2<D>::OuterConeIntensity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight2)->get_OuterConeIntensity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight2<D>::OuterConeIntensity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight2)->put_OuterConeIntensity(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight3<D>::MinAttenuationCutoff() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight3)->get_MinAttenuationCutoff(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight3<D>::MinAttenuationCutoff(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight3)->put_MinAttenuationCutoff(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpotLight3<D>::MaxAttenuationCutoff() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight3)->get_MaxAttenuationCutoff(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpotLight3<D>::MaxAttenuationCutoff(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpotLight3)->put_MaxAttenuationCutoff(value));
}

template <typename D> float consume_Windows_UI_Composition_ISpringScalarNaturalMotionAnimation<D>::DampingRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringScalarNaturalMotionAnimation)->get_DampingRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringScalarNaturalMotionAnimation<D>::DampingRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringScalarNaturalMotionAnimation)->put_DampingRatio(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_ISpringScalarNaturalMotionAnimation<D>::Period() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringScalarNaturalMotionAnimation)->get_Period(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringScalarNaturalMotionAnimation<D>::Period(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringScalarNaturalMotionAnimation)->put_Period(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpringVector2NaturalMotionAnimation<D>::DampingRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector2NaturalMotionAnimation)->get_DampingRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringVector2NaturalMotionAnimation<D>::DampingRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector2NaturalMotionAnimation)->put_DampingRatio(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_ISpringVector2NaturalMotionAnimation<D>::Period() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector2NaturalMotionAnimation)->get_Period(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringVector2NaturalMotionAnimation<D>::Period(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector2NaturalMotionAnimation)->put_Period(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_ISpringVector3NaturalMotionAnimation<D>::DampingRatio() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector3NaturalMotionAnimation)->get_DampingRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringVector3NaturalMotionAnimation<D>::DampingRatio(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector3NaturalMotionAnimation)->put_DampingRatio(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Composition_ISpringVector3NaturalMotionAnimation<D>::Period() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector3NaturalMotionAnimation)->get_Period(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpringVector3NaturalMotionAnimation<D>::Period(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpringVector3NaturalMotionAnimation)->put_Period(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBrush consume_Windows_UI_Composition_ISpriteVisual<D>::Brush() const
{
    Windows::UI::Composition::CompositionBrush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpriteVisual)->get_Brush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpriteVisual<D>::Brush(Windows::UI::Composition::CompositionBrush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpriteVisual)->put_Brush(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionShadow consume_Windows_UI_Composition_ISpriteVisual2<D>::Shadow() const
{
    Windows::UI::Composition::CompositionShadow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpriteVisual2)->get_Shadow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_ISpriteVisual2<D>::Shadow(Windows::UI::Composition::CompositionShadow const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::ISpriteVisual2)->put_Shadow(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Composition_IStepEasingFunction<D>::FinalStep() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->get_FinalStep(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IStepEasingFunction<D>::FinalStep(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->put_FinalStep(value));
}

template <typename D> int32_t consume_Windows_UI_Composition_IStepEasingFunction<D>::InitialStep() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->get_InitialStep(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IStepEasingFunction<D>::InitialStep(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->put_InitialStep(value));
}

template <typename D> bool consume_Windows_UI_Composition_IStepEasingFunction<D>::IsFinalStepSingleFrame() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->get_IsFinalStepSingleFrame(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IStepEasingFunction<D>::IsFinalStepSingleFrame(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->put_IsFinalStepSingleFrame(value));
}

template <typename D> bool consume_Windows_UI_Composition_IStepEasingFunction<D>::IsInitialStepSingleFrame() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->get_IsInitialStepSingleFrame(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IStepEasingFunction<D>::IsInitialStepSingleFrame(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->put_IsInitialStepSingleFrame(value));
}

template <typename D> int32_t consume_Windows_UI_Composition_IStepEasingFunction<D>::StepCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->get_StepCount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IStepEasingFunction<D>::StepCount(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IStepEasingFunction)->put_StepCount(value));
}

template <typename D> void consume_Windows_UI_Composition_IVector2KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2KeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IVector2KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float2 const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2KeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::FinalValue() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->get_FinalValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::FinalValue(optional<Windows::Foundation::Numerics::float2> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->put_FinalValue(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::InitialValue() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->get_InitialValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::InitialValue(optional<Windows::Foundation::Numerics::float2> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->put_InitialValue(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::InitialVelocity() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->get_InitialVelocity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector2NaturalMotionAnimation<D>::InitialVelocity(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector2NaturalMotionAnimation)->put_InitialVelocity(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IVector3KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3KeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IVector3KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float3 const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3KeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::FinalValue() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->get_FinalValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::FinalValue(optional<Windows::Foundation::Numerics::float3> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->put_FinalValue(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::InitialValue() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->get_InitialValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::InitialValue(optional<Windows::Foundation::Numerics::float3> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->put_InitialValue(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::InitialVelocity() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->get_InitialVelocity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVector3NaturalMotionAnimation<D>::InitialVelocity(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector3NaturalMotionAnimation)->put_InitialVelocity(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IVector4KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector4KeyFrameAnimation)->InsertKeyFrame(normalizedProgressKey, get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_IVector4KeyFrameAnimation<D>::InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float4 const& value, Windows::UI::Composition::CompositionEasingFunction const& easingFunction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVector4KeyFrameAnimation)->InsertKeyFrameWithEasingFunction(normalizedProgressKey, get_abi(value), get_abi(easingFunction)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_IVisual<D>::AnchorPoint() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_AnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::AnchorPoint(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_AnchorPoint(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBackfaceVisibility consume_Windows_UI_Composition_IVisual<D>::BackfaceVisibility() const
{
    Windows::UI::Composition::CompositionBackfaceVisibility value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_BackfaceVisibility(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::BackfaceVisibility(Windows::UI::Composition::CompositionBackfaceVisibility const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_BackfaceVisibility(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionBorderMode consume_Windows_UI_Composition_IVisual<D>::BorderMode() const
{
    Windows::UI::Composition::CompositionBorderMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_BorderMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::BorderMode(Windows::UI::Composition::CompositionBorderMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_BorderMode(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVisual<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::CenterPoint(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionClip consume_Windows_UI_Composition_IVisual<D>::Clip() const
{
    Windows::UI::Composition::CompositionClip value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Clip(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Clip(Windows::UI::Composition::CompositionClip const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Clip(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionCompositeMode consume_Windows_UI_Composition_IVisual<D>::CompositeMode() const
{
    Windows::UI::Composition::CompositionCompositeMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_CompositeMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::CompositeMode(Windows::UI::Composition::CompositionCompositeMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_CompositeMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Composition_IVisual<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_IsVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::IsVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_IsVisible(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVisual<D>::Offset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Offset(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Offset(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_IVisual<D>::Opacity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Opacity(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Opacity(value));
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_UI_Composition_IVisual<D>::Orientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Orientation(Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Orientation(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ContainerVisual consume_Windows_UI_Composition_IVisual<D>::Parent() const
{
    Windows::UI::Composition::ContainerVisual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_IVisual<D>::RotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_RotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::RotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_RotationAngle(value));
}

template <typename D> float consume_Windows_UI_Composition_IVisual<D>::RotationAngleInDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_RotationAngleInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::RotationAngleInDegrees(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_RotationAngleInDegrees(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVisual<D>::RotationAxis() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_RotationAxis(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::RotationAxis(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_RotationAxis(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVisual<D>::Scale() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Scale(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Scale(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_IVisual<D>::Size() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_Size(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::Size(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_Size(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_UI_Composition_IVisual<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual<D>::TransformMatrix(Windows::Foundation::Numerics::float4x4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual)->put_TransformMatrix(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_IVisual2<D>::ParentForTransform() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->get_ParentForTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual2<D>::ParentForTransform(Windows::UI::Composition::Visual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->put_ParentForTransform(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_IVisual2<D>::RelativeOffsetAdjustment() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->get_RelativeOffsetAdjustment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual2<D>::RelativeOffsetAdjustment(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->put_RelativeOffsetAdjustment(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Composition_IVisual2<D>::RelativeSizeAdjustment() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->get_RelativeSizeAdjustment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisual2<D>::RelativeSizeAdjustment(Windows::Foundation::Numerics::float2 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisual2)->put_RelativeSizeAdjustment(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Composition_IVisualCollection<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::InsertAbove(Windows::UI::Composition::Visual const& newChild, Windows::UI::Composition::Visual const& sibling) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->InsertAbove(get_abi(newChild), get_abi(sibling)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::InsertAtBottom(Windows::UI::Composition::Visual const& newChild) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->InsertAtBottom(get_abi(newChild)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::InsertAtTop(Windows::UI::Composition::Visual const& newChild) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->InsertAtTop(get_abi(newChild)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::InsertBelow(Windows::UI::Composition::Visual const& newChild, Windows::UI::Composition::Visual const& sibling) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->InsertBelow(get_abi(newChild), get_abi(sibling)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::Remove(Windows::UI::Composition::Visual const& child) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->Remove(get_abi(child)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualCollection<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualCollection)->RemoveAll());
}

template <typename D> int32_t consume_Windows_UI_Composition_IVisualUnorderedCollection<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualUnorderedCollection)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_IVisualUnorderedCollection<D>::Add(Windows::UI::Composition::Visual const& newVisual) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualUnorderedCollection)->Add(get_abi(newVisual)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualUnorderedCollection<D>::Remove(Windows::UI::Composition::Visual const& visual) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualUnorderedCollection)->Remove(get_abi(visual)));
}

template <typename D> void consume_Windows_UI_Composition_IVisualUnorderedCollection<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::IVisualUnorderedCollection)->RemoveAll());
}

template <typename D>
struct produce<D, Windows::UI::Composition::IAmbientLight> : produce_base<D, Windows::UI::Composition::IAmbientLight>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IAmbientLight2> : produce_base<D, Windows::UI::Composition::IAmbientLight2>
{
    int32_t WINRT_CALL get_Intensity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Intensity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Intensity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(void), float);
            this->shim().Intensity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IAnimationController> : produce_base<D, Windows::UI::Composition::IAnimationController>
{
    int32_t WINRT_CALL get_PlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaybackRate(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaybackRate, WINRT_WRAP(void), float);
            this->shim().PlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Progress(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Progress(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(void), float);
            this->shim().Progress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProgressBehavior(Windows::UI::Composition::AnimationControllerProgressBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgressBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationControllerProgressBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationControllerProgressBehavior>(this->shim().ProgressBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProgressBehavior(Windows::UI::Composition::AnimationControllerProgressBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgressBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationControllerProgressBehavior const&);
            this->shim().ProgressBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationControllerProgressBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IAnimationControllerStatics> : produce_base<D, Windows::UI::Composition::IAnimationControllerStatics>
{
    int32_t WINRT_CALL get_MaxPlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IAnimationObject> : produce_base<D, Windows::UI::Composition::IAnimationObject>
{
    int32_t WINRT_CALL PopulatePropertyInfo(void* propertyName, void* propertyInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulatePropertyInfo, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::AnimationPropertyInfo const&);
            this->shim().PopulatePropertyInfo(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Composition::AnimationPropertyInfo const*>(&propertyInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IAnimationPropertyInfo> : produce_base<D, Windows::UI::Composition::IAnimationPropertyInfo>
{
    int32_t WINRT_CALL get_AccessMode(Windows::UI::Composition::AnimationPropertyAccessMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessMode, WINRT_WRAP(Windows::UI::Composition::AnimationPropertyAccessMode));
            *value = detach_from<Windows::UI::Composition::AnimationPropertyAccessMode>(this->shim().AccessMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessMode(Windows::UI::Composition::AnimationPropertyAccessMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessMode, WINRT_WRAP(void), Windows::UI::Composition::AnimationPropertyAccessMode const&);
            this->shim().AccessMode(*reinterpret_cast<Windows::UI::Composition::AnimationPropertyAccessMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IBooleanKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IBooleanKeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, bool);
            this->shim().InsertKeyFrame(normalizedProgressKey, value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IBounceScalarNaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IBounceScalarNaturalMotionAnimation>
{
    int32_t WINRT_CALL get_Acceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Acceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Acceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(void), float);
            this->shim().Acceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Restitution(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Restitution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Restitution(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(void), float);
            this->shim().Restitution(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IBounceVector2NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IBounceVector2NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_Acceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Acceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Acceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(void), float);
            this->shim().Acceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Restitution(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Restitution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Restitution(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(void), float);
            this->shim().Restitution(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IBounceVector3NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IBounceVector3NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_Acceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Acceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Acceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Acceleration, WINRT_WRAP(void), float);
            this->shim().Acceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Restitution(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Restitution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Restitution(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restitution, WINRT_WRAP(void), float);
            this->shim().Restitution(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IColorKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IColorKeyFrameAnimation>
{
    int32_t WINRT_CALL get_InterpolationColorSpace(Windows::UI::Composition::CompositionColorSpace* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationColorSpace, WINRT_WRAP(Windows::UI::Composition::CompositionColorSpace));
            *value = detach_from<Windows::UI::Composition::CompositionColorSpace>(this->shim().InterpolationColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InterpolationColorSpace(Windows::UI::Composition::CompositionColorSpace value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationColorSpace, WINRT_WRAP(void), Windows::UI::Composition::CompositionColorSpace const&);
            this->shim().InterpolationColorSpace(*reinterpret_cast<Windows::UI::Composition::CompositionColorSpace const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::UI::Color const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, struct struct_Windows_UI_Color value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::UI::Color const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::UI::Color const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimation> : produce_base<D, Windows::UI::Composition::ICompositionAnimation>
{
    int32_t WINRT_CALL ClearAllParameters() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAllParameters, WINRT_WRAP(void));
            this->shim().ClearAllParameters();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearParameter(void* key) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearParameter, WINRT_WRAP(void), hstring const&);
            this->shim().ClearParameter(*reinterpret_cast<hstring const*>(&key));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorParameter(void* key, struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorParameter, WINRT_WRAP(void), hstring const&, Windows::UI::Color const&);
            this->shim().SetColorParameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMatrix3x2Parameter(void* key, Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMatrix3x2Parameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float3x2 const&);
            this->shim().SetMatrix3x2Parameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetMatrix4x4Parameter(void* key, Windows::Foundation::Numerics::float4x4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetMatrix4x4Parameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float4x4 const&);
            this->shim().SetMatrix4x4Parameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetQuaternionParameter(void* key, Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetQuaternionParameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::quaternion const&);
            this->shim().SetQuaternionParameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetReferenceParameter(void* key, void* compositionObject) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetReferenceParameter, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::CompositionObject const&);
            this->shim().SetReferenceParameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::UI::Composition::CompositionObject const*>(&compositionObject));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetScalarParameter(void* key, float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetScalarParameter, WINRT_WRAP(void), hstring const&, float);
            this->shim().SetScalarParameter(*reinterpret_cast<hstring const*>(&key), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVector2Parameter(void* key, Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVector2Parameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float2 const&);
            this->shim().SetVector2Parameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVector3Parameter(void* key, Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVector3Parameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().SetVector3Parameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVector4Parameter(void* key, Windows::Foundation::Numerics::float4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVector4Parameter, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float4 const&);
            this->shim().SetVector4Parameter(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimation2> : produce_base<D, Windows::UI::Composition::ICompositionAnimation2>
{
    int32_t WINRT_CALL SetBooleanParameter(void* key, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBooleanParameter, WINRT_WRAP(void), hstring const&, bool);
            this->shim().SetBooleanParameter(*reinterpret_cast<hstring const*>(&key), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Target(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(void), hstring const&);
            this->shim().Target(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimation3> : produce_base<D, Windows::UI::Composition::ICompositionAnimation3>
{
    int32_t WINRT_CALL get_InitialValueExpressions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValueExpressions, WINRT_WRAP(Windows::UI::Composition::InitialValueExpressionCollection));
            *value = detach_from<Windows::UI::Composition::InitialValueExpressionCollection>(this->shim().InitialValueExpressions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimation4> : produce_base<D, Windows::UI::Composition::ICompositionAnimation4>
{
    int32_t WINRT_CALL SetExpressionReferenceParameter(void* parameterName, void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetExpressionReferenceParameter, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::IAnimationObject const&);
            this->shim().SetExpressionReferenceParameter(*reinterpret_cast<hstring const*>(&parameterName), *reinterpret_cast<Windows::UI::Composition::IAnimationObject const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimationBase> : produce_base<D, Windows::UI::Composition::ICompositionAnimationBase>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimationFactory> : produce_base<D, Windows::UI::Composition::ICompositionAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionAnimationGroup> : produce_base<D, Windows::UI::Composition::ICompositionAnimationGroup>
{
    int32_t WINRT_CALL get_Count(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Count, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Add(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::UI::Composition::CompositionAnimation const&);
            this->shim().Add(*reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::CompositionAnimation const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAll, WINRT_WRAP(void));
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionBackdropBrush> : produce_base<D, Windows::UI::Composition::ICompositionBackdropBrush>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionBatchCompletedEventArgs> : produce_base<D, Windows::UI::Composition::ICompositionBatchCompletedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionBrush> : produce_base<D, Windows::UI::Composition::ICompositionBrush>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionBrushFactory> : produce_base<D, Windows::UI::Composition::ICompositionBrushFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionCapabilities> : produce_base<D, Windows::UI::Composition::ICompositionCapabilities>
{
    int32_t WINRT_CALL AreEffectsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreEffectsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreEffectsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AreEffectsFast(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreEffectsFast, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreEffectsFast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionCapabilities, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionCapabilities, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionCapabilitiesStatics> : produce_base<D, Windows::UI::Composition::ICompositionCapabilitiesStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Composition::CompositionCapabilities));
            *current = detach_from<Windows::UI::Composition::CompositionCapabilities>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionClip> : produce_base<D, Windows::UI::Composition::ICompositionClip>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionClip2> : produce_base<D, Windows::UI::Composition::ICompositionClip2>
{
    int32_t WINRT_CALL get_AnchorPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().AnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnchorPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().AnchorPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
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

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionClipFactory> : produce_base<D, Windows::UI::Composition::ICompositionClipFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionColorBrush> : produce_base<D, Windows::UI::Composition::ICompositionColorBrush>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionColorGradientStop> : produce_base<D, Windows::UI::Composition::ICompositionColorGradientStop>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), float);
            this->shim().Offset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionColorGradientStopCollection> : produce_base<D, Windows::UI::Composition::ICompositionColorGradientStopCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionCommitBatch> : produce_base<D, Windows::UI::Composition::ICompositionCommitBatch>
{
    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Completed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionContainerShape> : produce_base<D, Windows::UI::Composition::ICompositionContainerShape>
{
    int32_t WINRT_CALL get_Shapes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shapes, WINRT_WRAP(Windows::UI::Composition::CompositionShapeCollection));
            *value = detach_from<Windows::UI::Composition::CompositionShapeCollection>(this->shim().Shapes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionDrawingSurface> : produce_base<D, Windows::UI::Composition::ICompositionDrawingSurface>
{
    int32_t WINRT_CALL get_AlphaMode(Windows::Graphics::DirectX::DirectXAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaMode, WINRT_WRAP(Windows::Graphics::DirectX::DirectXAlphaMode));
            *value = detach_from<Windows::Graphics::DirectX::DirectXAlphaMode>(this->shim().AlphaMode());
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
struct produce<D, Windows::UI::Composition::ICompositionDrawingSurface2> : produce_base<D, Windows::UI::Composition::ICompositionDrawingSurface2>
{
    int32_t WINRT_CALL get_SizeInt32(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInt32, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().SizeInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resize(struct struct_Windows_Graphics_SizeInt32 sizePixels) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resize, WINRT_WRAP(void), Windows::Graphics::SizeInt32 const&);
            this->shim().Resize(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&sizePixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Scroll(struct struct_Windows_Graphics_PointInt32 offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scroll, WINRT_WRAP(void), Windows::Graphics::PointInt32 const&);
            this->shim().Scroll(*reinterpret_cast<Windows::Graphics::PointInt32 const*>(&offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScrollRect(struct struct_Windows_Graphics_PointInt32 offset, struct struct_Windows_Graphics_RectInt32 scrollRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scroll, WINRT_WRAP(void), Windows::Graphics::PointInt32 const&, Windows::Graphics::RectInt32 const&);
            this->shim().Scroll(*reinterpret_cast<Windows::Graphics::PointInt32 const*>(&offset), *reinterpret_cast<Windows::Graphics::RectInt32 const*>(&scrollRect));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScrollWithClip(struct struct_Windows_Graphics_PointInt32 offset, struct struct_Windows_Graphics_RectInt32 clipRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollWithClip, WINRT_WRAP(void), Windows::Graphics::PointInt32 const&, Windows::Graphics::RectInt32 const&);
            this->shim().ScrollWithClip(*reinterpret_cast<Windows::Graphics::PointInt32 const*>(&offset), *reinterpret_cast<Windows::Graphics::RectInt32 const*>(&clipRect));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScrollRectWithClip(struct struct_Windows_Graphics_PointInt32 offset, struct struct_Windows_Graphics_RectInt32 clipRect, struct struct_Windows_Graphics_RectInt32 scrollRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollWithClip, WINRT_WRAP(void), Windows::Graphics::PointInt32 const&, Windows::Graphics::RectInt32 const&, Windows::Graphics::RectInt32 const&);
            this->shim().ScrollWithClip(*reinterpret_cast<Windows::Graphics::PointInt32 const*>(&offset), *reinterpret_cast<Windows::Graphics::RectInt32 const*>(&clipRect), *reinterpret_cast<Windows::Graphics::RectInt32 const*>(&scrollRect));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionDrawingSurfaceFactory> : produce_base<D, Windows::UI::Composition::ICompositionDrawingSurfaceFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEasingFunction> : produce_base<D, Windows::UI::Composition::ICompositionEasingFunction>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEasingFunctionFactory> : produce_base<D, Windows::UI::Composition::ICompositionEasingFunctionFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEffectBrush> : produce_base<D, Windows::UI::Composition::ICompositionEffectBrush>
{
    int32_t WINRT_CALL GetSourceParameter(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSourceParameter, WINRT_WRAP(Windows::UI::Composition::CompositionBrush), hstring const&);
            *result = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().GetSourceParameter(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSourceParameter(void* name, void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSourceParameter, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::CompositionBrush const&);
            this->shim().SetSourceParameter(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEffectFactory> : produce_base<D, Windows::UI::Composition::ICompositionEffectFactory>
{
    int32_t WINRT_CALL CreateBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBrush, WINRT_WRAP(Windows::UI::Composition::CompositionEffectBrush));
            *result = detach_from<Windows::UI::Composition::CompositionEffectBrush>(this->shim().CreateBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LoadStatus(Windows::UI::Composition::CompositionEffectFactoryLoadStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadStatus, WINRT_WRAP(Windows::UI::Composition::CompositionEffectFactoryLoadStatus));
            *value = detach_from<Windows::UI::Composition::CompositionEffectFactoryLoadStatus>(this->shim().LoadStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEffectSourceParameter> : produce_base<D, Windows::UI::Composition::ICompositionEffectSourceParameter>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEffectSourceParameterFactory> : produce_base<D, Windows::UI::Composition::ICompositionEffectSourceParameterFactory>
{
    int32_t WINRT_CALL Create(void* name, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::CompositionEffectSourceParameter), hstring const&);
            *instance = detach_from<Windows::UI::Composition::CompositionEffectSourceParameter>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionEllipseGeometry> : produce_base<D, Windows::UI::Composition::ICompositionEllipseGeometry>
{
    int32_t WINRT_CALL get_Center(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Center(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Center(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Radius(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Radius(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Radius(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGeometricClip> : produce_base<D, Windows::UI::Composition::ICompositionGeometricClip>
{
    int32_t WINRT_CALL get_Geometry(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geometry, WINRT_WRAP(Windows::UI::Composition::CompositionGeometry));
            *value = detach_from<Windows::UI::Composition::CompositionGeometry>(this->shim().Geometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Geometry(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geometry, WINRT_WRAP(void), Windows::UI::Composition::CompositionGeometry const&);
            this->shim().Geometry(*reinterpret_cast<Windows::UI::Composition::CompositionGeometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewBox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewBox, WINRT_WRAP(Windows::UI::Composition::CompositionViewBox));
            *value = detach_from<Windows::UI::Composition::CompositionViewBox>(this->shim().ViewBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewBox(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewBox, WINRT_WRAP(void), Windows::UI::Composition::CompositionViewBox const&);
            this->shim().ViewBox(*reinterpret_cast<Windows::UI::Composition::CompositionViewBox const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGeometry> : produce_base<D, Windows::UI::Composition::ICompositionGeometry>
{
    int32_t WINRT_CALL get_TrimEnd(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimEnd, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TrimEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimEnd(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimEnd, WINRT_WRAP(void), float);
            this->shim().TrimEnd(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimOffset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimOffset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TrimOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimOffset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimOffset, WINRT_WRAP(void), float);
            this->shim().TrimOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrimStart(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimStart, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TrimStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrimStart(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrimStart, WINRT_WRAP(void), float);
            this->shim().TrimStart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGeometryFactory> : produce_base<D, Windows::UI::Composition::ICompositionGeometryFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGradientBrush> : produce_base<D, Windows::UI::Composition::ICompositionGradientBrush>
{
    int32_t WINRT_CALL get_AnchorPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().AnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnchorPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().AnchorPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorStops(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorStops, WINRT_WRAP(Windows::UI::Composition::CompositionColorGradientStopCollection));
            *value = detach_from<Windows::UI::Composition::CompositionColorGradientStopCollection>(this->shim().ColorStops());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendMode(Windows::UI::Composition::CompositionGradientExtendMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendMode, WINRT_WRAP(Windows::UI::Composition::CompositionGradientExtendMode));
            *value = detach_from<Windows::UI::Composition::CompositionGradientExtendMode>(this->shim().ExtendMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExtendMode(Windows::UI::Composition::CompositionGradientExtendMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendMode, WINRT_WRAP(void), Windows::UI::Composition::CompositionGradientExtendMode const&);
            this->shim().ExtendMode(*reinterpret_cast<Windows::UI::Composition::CompositionGradientExtendMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterpolationSpace(Windows::UI::Composition::CompositionColorSpace* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationSpace, WINRT_WRAP(Windows::UI::Composition::CompositionColorSpace));
            *value = detach_from<Windows::UI::Composition::CompositionColorSpace>(this->shim().InterpolationSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InterpolationSpace(Windows::UI::Composition::CompositionColorSpace value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationSpace, WINRT_WRAP(void), Windows::UI::Composition::CompositionColorSpace const&);
            this->shim().InterpolationSpace(*reinterpret_cast<Windows::UI::Composition::CompositionColorSpace const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
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

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGradientBrush2> : produce_base<D, Windows::UI::Composition::ICompositionGradientBrush2>
{
    int32_t WINRT_CALL get_MappingMode(Windows::UI::Composition::CompositionMappingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MappingMode, WINRT_WRAP(Windows::UI::Composition::CompositionMappingMode));
            *value = detach_from<Windows::UI::Composition::CompositionMappingMode>(this->shim().MappingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MappingMode(Windows::UI::Composition::CompositionMappingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MappingMode, WINRT_WRAP(void), Windows::UI::Composition::CompositionMappingMode const&);
            this->shim().MappingMode(*reinterpret_cast<Windows::UI::Composition::CompositionMappingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGradientBrushFactory> : produce_base<D, Windows::UI::Composition::ICompositionGradientBrushFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGraphicsDevice> : produce_base<D, Windows::UI::Composition::ICompositionGraphicsDevice>
{
    int32_t WINRT_CALL CreateDrawingSurface(Windows::Foundation::Size sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode alphaMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDrawingSurface, WINRT_WRAP(Windows::UI::Composition::CompositionDrawingSurface), Windows::Foundation::Size const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXAlphaMode const&);
            *result = detach_from<Windows::UI::Composition::CompositionDrawingSurface>(this->shim().CreateDrawingSurface(*reinterpret_cast<Windows::Foundation::Size const*>(&sizePixels), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXAlphaMode const*>(&alphaMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RenderingDeviceReplaced(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderingDeviceReplaced, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionGraphicsDevice, Windows::UI::Composition::RenderingDeviceReplacedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RenderingDeviceReplaced(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Composition::CompositionGraphicsDevice, Windows::UI::Composition::RenderingDeviceReplacedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RenderingDeviceReplaced(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RenderingDeviceReplaced, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RenderingDeviceReplaced(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGraphicsDevice2> : produce_base<D, Windows::UI::Composition::ICompositionGraphicsDevice2>
{
    int32_t WINRT_CALL CreateDrawingSurface2(struct struct_Windows_Graphics_SizeInt32 sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode alphaMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDrawingSurface2, WINRT_WRAP(Windows::UI::Composition::CompositionDrawingSurface), Windows::Graphics::SizeInt32 const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXAlphaMode const&);
            *result = detach_from<Windows::UI::Composition::CompositionDrawingSurface>(this->shim().CreateDrawingSurface2(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&sizePixels), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXAlphaMode const*>(&alphaMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVirtualDrawingSurface(struct struct_Windows_Graphics_SizeInt32 sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode alphaMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVirtualDrawingSurface, WINRT_WRAP(Windows::UI::Composition::CompositionVirtualDrawingSurface), Windows::Graphics::SizeInt32 const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXAlphaMode const&);
            *result = detach_from<Windows::UI::Composition::CompositionVirtualDrawingSurface>(this->shim().CreateVirtualDrawingSurface(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&sizePixels), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXAlphaMode const*>(&alphaMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionGraphicsDevice3> : produce_base<D, Windows::UI::Composition::ICompositionGraphicsDevice3>
{
    int32_t WINRT_CALL CreateMipmapSurface(struct struct_Windows_Graphics_SizeInt32 sizePixels, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXAlphaMode alphaMode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMipmapSurface, WINRT_WRAP(Windows::UI::Composition::CompositionMipmapSurface), Windows::Graphics::SizeInt32 const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXAlphaMode const&);
            *result = detach_from<Windows::UI::Composition::CompositionMipmapSurface>(this->shim().CreateMipmapSurface(*reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&sizePixels), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXAlphaMode const*>(&alphaMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Trim() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trim, WINRT_WRAP(void));
            this->shim().Trim();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLight> : produce_base<D, Windows::UI::Composition::ICompositionLight>
{
    int32_t WINRT_CALL get_Targets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Targets, WINRT_WRAP(Windows::UI::Composition::VisualUnorderedCollection));
            *value = detach_from<Windows::UI::Composition::VisualUnorderedCollection>(this->shim().Targets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLight2> : produce_base<D, Windows::UI::Composition::ICompositionLight2>
{
    int32_t WINRT_CALL get_ExclusionsFromTargets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExclusionsFromTargets, WINRT_WRAP(Windows::UI::Composition::VisualUnorderedCollection));
            *value = detach_from<Windows::UI::Composition::VisualUnorderedCollection>(this->shim().ExclusionsFromTargets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLight3> : produce_base<D, Windows::UI::Composition::ICompositionLight3>
{
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

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLightFactory> : produce_base<D, Windows::UI::Composition::ICompositionLightFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLineGeometry> : produce_base<D, Windows::UI::Composition::ICompositionLineGeometry>
{
    int32_t WINRT_CALL get_Start(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Start());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Start(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Start(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_End(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(End, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().End());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_End(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(End, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().End(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionLinearGradientBrush> : produce_base<D, Windows::UI::Composition::ICompositionLinearGradientBrush>
{
    int32_t WINRT_CALL get_EndPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().EndPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().EndPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().StartPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().StartPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionMaskBrush> : produce_base<D, Windows::UI::Composition::ICompositionMaskBrush>
{
    int32_t WINRT_CALL get_Mask(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mask, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Mask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mask(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mask, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Mask(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Source(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionMipmapSurface> : produce_base<D, Windows::UI::Composition::ICompositionMipmapSurface>
{
    int32_t WINRT_CALL get_LevelCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LevelCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlphaMode(Windows::Graphics::DirectX::DirectXAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlphaMode, WINRT_WRAP(Windows::Graphics::DirectX::DirectXAlphaMode));
            *value = detach_from<Windows::Graphics::DirectX::DirectXAlphaMode>(this->shim().AlphaMode());
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

    int32_t WINRT_CALL get_SizeInt32(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInt32, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().SizeInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrawingSurfaceForLevel(uint32_t level, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrawingSurfaceForLevel, WINRT_WRAP(Windows::UI::Composition::CompositionDrawingSurface), uint32_t);
            *result = detach_from<Windows::UI::Composition::CompositionDrawingSurface>(this->shim().GetDrawingSurfaceForLevel(level));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionNineGridBrush> : produce_base<D, Windows::UI::Composition::ICompositionNineGridBrush>
{
    int32_t WINRT_CALL get_BottomInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BottomInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BottomInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInset, WINRT_WRAP(void), float);
            this->shim().BottomInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BottomInsetScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInsetScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BottomInsetScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BottomInsetScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInsetScale, WINRT_WRAP(void), float);
            this->shim().BottomInsetScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCenterHollow(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCenterHollow, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCenterHollow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCenterHollow(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCenterHollow, WINRT_WRAP(void), bool);
            this->shim().IsCenterHollow(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LeftInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInset, WINRT_WRAP(void), float);
            this->shim().LeftInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftInsetScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInsetScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LeftInsetScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftInsetScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInsetScale, WINRT_WRAP(void), float);
            this->shim().LeftInsetScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RightInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInset, WINRT_WRAP(void), float);
            this->shim().RightInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightInsetScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInsetScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RightInsetScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightInsetScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInsetScale, WINRT_WRAP(void), float);
            this->shim().RightInsetScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Source(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TopInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TopInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TopInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInset, WINRT_WRAP(void), float);
            this->shim().TopInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TopInsetScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInsetScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TopInsetScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TopInsetScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInsetScale, WINRT_WRAP(void), float);
            this->shim().TopInsetScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInsets(float inset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInsets, WINRT_WRAP(void), float);
            this->shim().SetInsets(inset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInsetsWithValues(float left, float top, float right, float bottom) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInsets, WINRT_WRAP(void), float, float, float, float);
            this->shim().SetInsets(left, top, right, bottom);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInsetScales(float scale) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInsetScales, WINRT_WRAP(void), float);
            this->shim().SetInsetScales(scale);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInsetScalesWithValues(float left, float top, float right, float bottom) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInsetScales, WINRT_WRAP(void), float, float, float, float);
            this->shim().SetInsetScales(left, top, right, bottom);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObject> : produce_base<D, Windows::UI::Composition::ICompositionObject>
{
    int32_t WINRT_CALL get_Compositor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compositor, WINRT_WRAP(Windows::UI::Composition::Compositor));
            *value = detach_from<Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Dispatcher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dispatcher, WINRT_WRAP(Windows::UI::Core::CoreDispatcher));
            *value = detach_from<Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::UI::Composition::CompositionPropertySet));
            *value = detach_from<Windows::UI::Composition::CompositionPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAnimation(void* propertyName, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAnimation, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::CompositionAnimation const&);
            this->shim().StartAnimation(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAnimation(void* propertyName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAnimation, WINRT_WRAP(void), hstring const&);
            this->shim().StopAnimation(*reinterpret_cast<hstring const*>(&propertyName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObject2> : produce_base<D, Windows::UI::Composition::ICompositionObject2>
{
    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Comment(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(void), hstring const&);
            this->shim().Comment(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImplicitAnimations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImplicitAnimations, WINRT_WRAP(Windows::UI::Composition::ImplicitAnimationCollection));
            *value = detach_from<Windows::UI::Composition::ImplicitAnimationCollection>(this->shim().ImplicitAnimations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ImplicitAnimations(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImplicitAnimations, WINRT_WRAP(void), Windows::UI::Composition::ImplicitAnimationCollection const&);
            this->shim().ImplicitAnimations(*reinterpret_cast<Windows::UI::Composition::ImplicitAnimationCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAnimationGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAnimationGroup, WINRT_WRAP(void), Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().StartAnimationGroup(*reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAnimationGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAnimationGroup, WINRT_WRAP(void), Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().StopAnimationGroup(*reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObject3> : produce_base<D, Windows::UI::Composition::ICompositionObject3>
{
    int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispatcherQueue, WINRT_WRAP(Windows::System::DispatcherQueue));
            *value = detach_from<Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObject4> : produce_base<D, Windows::UI::Composition::ICompositionObject4>
{
    int32_t WINRT_CALL TryGetAnimationController(void* propertyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAnimationController, WINRT_WRAP(Windows::UI::Composition::AnimationController), hstring const&);
            *result = detach_from<Windows::UI::Composition::AnimationController>(this->shim().TryGetAnimationController(*reinterpret_cast<hstring const*>(&propertyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObjectFactory> : produce_base<D, Windows::UI::Composition::ICompositionObjectFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionObjectStatics> : produce_base<D, Windows::UI::Composition::ICompositionObjectStatics>
{
    int32_t WINRT_CALL StartAnimationWithIAnimationObject(void* target, void* propertyName, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAnimationWithIAnimationObject, WINRT_WRAP(void), Windows::UI::Composition::IAnimationObject const&, hstring const&, Windows::UI::Composition::CompositionAnimation const&);
            this->shim().StartAnimationWithIAnimationObject(*reinterpret_cast<Windows::UI::Composition::IAnimationObject const*>(&target), *reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAnimationGroupWithIAnimationObject(void* target, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAnimationGroupWithIAnimationObject, WINRT_WRAP(void), Windows::UI::Composition::IAnimationObject const&, Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().StartAnimationGroupWithIAnimationObject(*reinterpret_cast<Windows::UI::Composition::IAnimationObject const*>(&target), *reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionPath> : produce_base<D, Windows::UI::Composition::ICompositionPath>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionPathFactory> : produce_base<D, Windows::UI::Composition::ICompositionPathFactory>
{
    int32_t WINRT_CALL Create(void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::CompositionPath), Windows::Graphics::IGeometrySource2D const&);
            *result = detach_from<Windows::UI::Composition::CompositionPath>(this->shim().Create(*reinterpret_cast<Windows::Graphics::IGeometrySource2D const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionPathGeometry> : produce_base<D, Windows::UI::Composition::ICompositionPathGeometry>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::UI::Composition::CompositionPath));
            *value = detach_from<Windows::UI::Composition::CompositionPath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::UI::Composition::CompositionPath const&);
            this->shim().Path(*reinterpret_cast<Windows::UI::Composition::CompositionPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadow> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadow>
{
    int32_t WINRT_CALL get_BlurRadiusMultiplier(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlurRadiusMultiplier, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BlurRadiusMultiplier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BlurRadiusMultiplier(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlurRadiusMultiplier, WINRT_WRAP(void), float);
            this->shim().BlurRadiusMultiplier(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Casters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Casters, WINRT_WRAP(Windows::UI::Composition::CompositionProjectedShadowCasterCollection));
            *value = detach_from<Windows::UI::Composition::CompositionProjectedShadowCasterCollection>(this->shim().Casters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSource, WINRT_WRAP(Windows::UI::Composition::CompositionLight));
            *value = detach_from<Windows::UI::Composition::CompositionLight>(this->shim().LightSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LightSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSource, WINRT_WRAP(void), Windows::UI::Composition::CompositionLight const&);
            this->shim().LightSource(*reinterpret_cast<Windows::UI::Composition::CompositionLight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBlurRadius(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBlurRadius, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxBlurRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxBlurRadius(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBlurRadius, WINRT_WRAP(void), float);
            this->shim().MaxBlurRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinBlurRadius(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinBlurRadius, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinBlurRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinBlurRadius(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinBlurRadius, WINRT_WRAP(void), float);
            this->shim().MinBlurRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Receivers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Receivers, WINRT_WRAP(Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection));
            *value = detach_from<Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection>(this->shim().Receivers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadowCaster> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadowCaster>
{
    int32_t WINRT_CALL get_Brush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brush, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Brush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Brush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brush, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Brush(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CastingVisual(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CastingVisual, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().CastingVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CastingVisual(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CastingVisual, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().CastingVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadowCasterCollection> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadowCasterCollection>
{
    int32_t WINRT_CALL get_Count(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Count, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAbove(void* newCaster, void* reference) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAbove, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowCaster const&, Windows::UI::Composition::CompositionProjectedShadowCaster const&);
            this->shim().InsertAbove(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&newCaster), *reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&reference));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAtBottom(void* newCaster) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAtBottom, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowCaster const&);
            this->shim().InsertAtBottom(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&newCaster));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAtTop(void* newCaster) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAtTop, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowCaster const&);
            this->shim().InsertAtTop(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&newCaster));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertBelow(void* newCaster, void* reference) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertBelow, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowCaster const&, Windows::UI::Composition::CompositionProjectedShadowCaster const&);
            this->shim().InsertBelow(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&newCaster), *reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&reference));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* caster) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowCaster const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowCaster const*>(&caster));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAll, WINRT_WRAP(void));
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics>
{
    int32_t WINRT_CALL get_MaxRespectedCasters(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRespectedCasters, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxRespectedCasters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadowReceiver> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadowReceiver>
{
    int32_t WINRT_CALL get_ReceivingVisual(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivingVisual, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().ReceivingVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReceivingVisual(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReceivingVisual, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().ReceivingVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection> : produce_base<D, Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection>
{
    int32_t WINRT_CALL Add(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowReceiver const&);
            this->shim().Add(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowReceiver const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Count(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Count, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::CompositionProjectedShadowReceiver const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::CompositionProjectedShadowReceiver const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAll, WINRT_WRAP(void));
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionPropertySet> : produce_base<D, Windows::UI::Composition::ICompositionPropertySet>
{
    int32_t WINRT_CALL InsertColor(void* propertyName, struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertColor, WINRT_WRAP(void), hstring const&, Windows::UI::Color const&);
            this->shim().InsertColor(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertMatrix3x2(void* propertyName, Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertMatrix3x2, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float3x2 const&);
            this->shim().InsertMatrix3x2(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertMatrix4x4(void* propertyName, Windows::Foundation::Numerics::float4x4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertMatrix4x4, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float4x4 const&);
            this->shim().InsertMatrix4x4(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertQuaternion(void* propertyName, Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertQuaternion, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::quaternion const&);
            this->shim().InsertQuaternion(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertScalar(void* propertyName, float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertScalar, WINRT_WRAP(void), hstring const&, float);
            this->shim().InsertScalar(*reinterpret_cast<hstring const*>(&propertyName), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertVector2(void* propertyName, Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertVector2, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float2 const&);
            this->shim().InsertVector2(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertVector3(void* propertyName, Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertVector3, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float3 const&);
            this->shim().InsertVector3(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertVector4(void* propertyName, Windows::Foundation::Numerics::float4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertVector4, WINRT_WRAP(void), hstring const&, Windows::Foundation::Numerics::float4 const&);
            this->shim().InsertVector4(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetColor(void* propertyName, struct struct_Windows_UI_Color* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetColor, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::UI::Color&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetColor(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Color*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetMatrix3x2(void* propertyName, Windows::Foundation::Numerics::float3x2* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetMatrix3x2, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::float3x2&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetMatrix3x2(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float3x2*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetMatrix4x4(void* propertyName, Windows::Foundation::Numerics::float4x4* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetMatrix4x4, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::float4x4&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetMatrix4x4(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float4x4*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetQuaternion(void* propertyName, Windows::Foundation::Numerics::quaternion* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetQuaternion, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::quaternion&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetQuaternion(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::quaternion*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetScalar(void* propertyName, float* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetScalar, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, float&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetScalar(*reinterpret_cast<hstring const*>(&propertyName), *value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetVector2(void* propertyName, Windows::Foundation::Numerics::float2* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetVector2, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::float2&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetVector2(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float2*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetVector3(void* propertyName, Windows::Foundation::Numerics::float3* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetVector3, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::float3&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetVector3(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float3*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetVector4(void* propertyName, Windows::Foundation::Numerics::float4* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetVector4, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, Windows::Foundation::Numerics::float4&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetVector4(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::Foundation::Numerics::float4*>(value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionPropertySet2> : produce_base<D, Windows::UI::Composition::ICompositionPropertySet2>
{
    int32_t WINRT_CALL InsertBoolean(void* propertyName, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertBoolean, WINRT_WRAP(void), hstring const&, bool);
            this->shim().InsertBoolean(*reinterpret_cast<hstring const*>(&propertyName), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetBoolean(void* propertyName, bool* value, Windows::UI::Composition::CompositionGetValueStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetBoolean, WINRT_WRAP(Windows::UI::Composition::CompositionGetValueStatus), hstring const&, bool&);
            *result = detach_from<Windows::UI::Composition::CompositionGetValueStatus>(this->shim().TryGetBoolean(*reinterpret_cast<hstring const*>(&propertyName), *value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionRadialGradientBrush> : produce_base<D, Windows::UI::Composition::ICompositionRadialGradientBrush>
{
    int32_t WINRT_CALL get_EllipseCenter(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseCenter, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().EllipseCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EllipseCenter(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseCenter, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().EllipseCenter(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EllipseRadius(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseRadius, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().EllipseRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EllipseRadius(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EllipseRadius, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().EllipseRadius(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GradientOriginOffset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GradientOriginOffset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().GradientOriginOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GradientOriginOffset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GradientOriginOffset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().GradientOriginOffset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionRectangleGeometry> : produce_base<D, Windows::UI::Composition::ICompositionRectangleGeometry>
{
    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionRoundedRectangleGeometry> : produce_base<D, Windows::UI::Composition::ICompositionRoundedRectangleGeometry>
{
    int32_t WINRT_CALL get_CornerRadius(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CornerRadius, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().CornerRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CornerRadius(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CornerRadius, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().CornerRadius(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionScopedBatch> : produce_base<D, Windows::UI::Composition::ICompositionScopedBatch>
{
    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL End() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(End, WINRT_WRAP(void));
            this->shim().End();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Suspend() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suspend, WINRT_WRAP(void));
            this->shim().Suspend();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Composition::CompositionBatchCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Completed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionShadow> : produce_base<D, Windows::UI::Composition::ICompositionShadow>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionShadowFactory> : produce_base<D, Windows::UI::Composition::ICompositionShadowFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionShape> : produce_base<D, Windows::UI::Composition::ICompositionShape>
{
    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
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

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionShapeFactory> : produce_base<D, Windows::UI::Composition::ICompositionShapeFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionSpriteShape> : produce_base<D, Windows::UI::Composition::ICompositionSpriteShape>
{
    int32_t WINRT_CALL get_FillBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillBrush, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().FillBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FillBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillBrush, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().FillBrush(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Geometry(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geometry, WINRT_WRAP(Windows::UI::Composition::CompositionGeometry));
            *value = detach_from<Windows::UI::Composition::CompositionGeometry>(this->shim().Geometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Geometry(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geometry, WINRT_WRAP(void), Windows::UI::Composition::CompositionGeometry const&);
            this->shim().Geometry(*reinterpret_cast<Windows::UI::Composition::CompositionGeometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStrokeNonScaling(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStrokeNonScaling, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStrokeNonScaling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStrokeNonScaling(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStrokeNonScaling, WINRT_WRAP(void), bool);
            this->shim().IsStrokeNonScaling(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeBrush, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().StrokeBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeBrush, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().StrokeBrush(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashArray(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashArray, WINRT_WRAP(Windows::UI::Composition::CompositionStrokeDashArray));
            *value = detach_from<Windows::UI::Composition::CompositionStrokeDashArray>(this->shim().StrokeDashArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashCap(Windows::UI::Composition::CompositionStrokeCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashCap, WINRT_WRAP(Windows::UI::Composition::CompositionStrokeCap));
            *value = detach_from<Windows::UI::Composition::CompositionStrokeCap>(this->shim().StrokeDashCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashCap(Windows::UI::Composition::CompositionStrokeCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashCap, WINRT_WRAP(void), Windows::UI::Composition::CompositionStrokeCap const&);
            this->shim().StrokeDashCap(*reinterpret_cast<Windows::UI::Composition::CompositionStrokeCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashOffset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashOffset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().StrokeDashOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashOffset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashOffset, WINRT_WRAP(void), float);
            this->shim().StrokeDashOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeEndCap(Windows::UI::Composition::CompositionStrokeCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEndCap, WINRT_WRAP(Windows::UI::Composition::CompositionStrokeCap));
            *value = detach_from<Windows::UI::Composition::CompositionStrokeCap>(this->shim().StrokeEndCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeEndCap(Windows::UI::Composition::CompositionStrokeCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeEndCap, WINRT_WRAP(void), Windows::UI::Composition::CompositionStrokeCap const&);
            this->shim().StrokeEndCap(*reinterpret_cast<Windows::UI::Composition::CompositionStrokeCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeLineJoin(Windows::UI::Composition::CompositionStrokeLineJoin* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeLineJoin, WINRT_WRAP(Windows::UI::Composition::CompositionStrokeLineJoin));
            *value = detach_from<Windows::UI::Composition::CompositionStrokeLineJoin>(this->shim().StrokeLineJoin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeLineJoin(Windows::UI::Composition::CompositionStrokeLineJoin value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeLineJoin, WINRT_WRAP(void), Windows::UI::Composition::CompositionStrokeLineJoin const&);
            this->shim().StrokeLineJoin(*reinterpret_cast<Windows::UI::Composition::CompositionStrokeLineJoin const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeMiterLimit(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeMiterLimit, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().StrokeMiterLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeMiterLimit(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeMiterLimit, WINRT_WRAP(void), float);
            this->shim().StrokeMiterLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeStartCap(Windows::UI::Composition::CompositionStrokeCap* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartCap, WINRT_WRAP(Windows::UI::Composition::CompositionStrokeCap));
            *value = detach_from<Windows::UI::Composition::CompositionStrokeCap>(this->shim().StrokeStartCap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeStartCap(Windows::UI::Composition::CompositionStrokeCap value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeStartCap, WINRT_WRAP(void), Windows::UI::Composition::CompositionStrokeCap const&);
            this->shim().StrokeStartCap(*reinterpret_cast<Windows::UI::Composition::CompositionStrokeCap const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThickness(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().StrokeThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeThickness(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(void), float);
            this->shim().StrokeThickness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionSurface> : produce_base<D, Windows::UI::Composition::ICompositionSurface>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionSurfaceBrush> : produce_base<D, Windows::UI::Composition::ICompositionSurfaceBrush>
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

    int32_t WINRT_CALL get_HorizontalAlignmentRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalAlignmentRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(void), float);
            this->shim().HorizontalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stretch(Windows::UI::Composition::CompositionStretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(Windows::UI::Composition::CompositionStretch));
            *value = detach_from<Windows::UI::Composition::CompositionStretch>(this->shim().Stretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Stretch(Windows::UI::Composition::CompositionStretch value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(void), Windows::UI::Composition::CompositionStretch const&);
            this->shim().Stretch(*reinterpret_cast<Windows::UI::Composition::CompositionStretch const*>(&value));
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

    int32_t WINRT_CALL get_VerticalAlignmentRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalAlignmentRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(void), float);
            this->shim().VerticalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionSurfaceBrush2> : produce_base<D, Windows::UI::Composition::ICompositionSurfaceBrush2>
{
    int32_t WINRT_CALL get_AnchorPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().AnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnchorPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().AnchorPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
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

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float3x2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float3x2 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionSurfaceBrush3> : produce_base<D, Windows::UI::Composition::ICompositionSurfaceBrush3>
{
    int32_t WINRT_CALL get_SnapToPixels(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SnapToPixels, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SnapToPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SnapToPixels(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SnapToPixels, WINRT_WRAP(void), bool);
            this->shim().SnapToPixels(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionTarget> : produce_base<D, Windows::UI::Composition::ICompositionTarget>
{
    int32_t WINRT_CALL get_Root(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Root, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().Root());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Root(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Root, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Root(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionTargetFactory> : produce_base<D, Windows::UI::Composition::ICompositionTargetFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionTransform> : produce_base<D, Windows::UI::Composition::ICompositionTransform>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionTransformFactory> : produce_base<D, Windows::UI::Composition::ICompositionTransformFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionViewBox> : produce_base<D, Windows::UI::Composition::ICompositionViewBox>
{
    int32_t WINRT_CALL get_HorizontalAlignmentRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalAlignmentRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(void), float);
            this->shim().HorizontalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stretch(Windows::UI::Composition::CompositionStretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(Windows::UI::Composition::CompositionStretch));
            *value = detach_from<Windows::UI::Composition::CompositionStretch>(this->shim().Stretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Stretch(Windows::UI::Composition::CompositionStretch value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stretch, WINRT_WRAP(void), Windows::UI::Composition::CompositionStretch const&);
            this->shim().Stretch(*reinterpret_cast<Windows::UI::Composition::CompositionStretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalAlignmentRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalAlignmentRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(void), float);
            this->shim().VerticalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionVirtualDrawingSurface> : produce_base<D, Windows::UI::Composition::ICompositionVirtualDrawingSurface>
{
    int32_t WINRT_CALL Trim(uint32_t __rectsSize, struct struct_Windows_Graphics_RectInt32* rects) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trim, WINRT_WRAP(void), array_view<Windows::Graphics::RectInt32 const>);
            this->shim().Trim(array_view<Windows::Graphics::RectInt32 const>(reinterpret_cast<Windows::Graphics::RectInt32 const *>(rects), reinterpret_cast<Windows::Graphics::RectInt32 const *>(rects) + __rectsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionVirtualDrawingSurfaceFactory> : produce_base<D, Windows::UI::Composition::ICompositionVirtualDrawingSurfaceFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositionVisualSurface> : produce_base<D, Windows::UI::Composition::ICompositionVisualSurface>
{
    int32_t WINRT_CALL get_SourceVisual(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceVisual, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().SourceVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceVisual(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceVisual, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().SourceVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceOffset(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceOffset, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().SourceOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceOffset(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceOffset, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().SourceOffset(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceSize(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceSize, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().SourceSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceSize(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceSize, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().SourceSize(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor> : produce_base<D, Windows::UI::Composition::ICompositor>
{
    int32_t WINRT_CALL CreateColorKeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateColorKeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::ColorKeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::ColorKeyFrameAnimation>(this->shim().CreateColorKeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateColorBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateColorBrush, WINRT_WRAP(Windows::UI::Composition::CompositionColorBrush));
            *result = detach_from<Windows::UI::Composition::CompositionColorBrush>(this->shim().CreateColorBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateColorBrushWithColor(struct struct_Windows_UI_Color color, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateColorBrush, WINRT_WRAP(Windows::UI::Composition::CompositionColorBrush), Windows::UI::Color const&);
            *result = detach_from<Windows::UI::Composition::CompositionColorBrush>(this->shim().CreateColorBrush(*reinterpret_cast<Windows::UI::Color const*>(&color)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateContainerVisual(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateContainerVisual, WINRT_WRAP(Windows::UI::Composition::ContainerVisual));
            *result = detach_from<Windows::UI::Composition::ContainerVisual>(this->shim().CreateContainerVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCubicBezierEasingFunction(Windows::Foundation::Numerics::float2 controlPoint1, Windows::Foundation::Numerics::float2 controlPoint2, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCubicBezierEasingFunction, WINRT_WRAP(Windows::UI::Composition::CubicBezierEasingFunction), Windows::Foundation::Numerics::float2 const&, Windows::Foundation::Numerics::float2 const&);
            *result = detach_from<Windows::UI::Composition::CubicBezierEasingFunction>(this->shim().CreateCubicBezierEasingFunction(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&controlPoint1), *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&controlPoint2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEffectFactory(void* graphicsEffect, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEffectFactory, WINRT_WRAP(Windows::UI::Composition::CompositionEffectFactory), Windows::Graphics::Effects::IGraphicsEffect const&);
            *result = detach_from<Windows::UI::Composition::CompositionEffectFactory>(this->shim().CreateEffectFactory(*reinterpret_cast<Windows::Graphics::Effects::IGraphicsEffect const*>(&graphicsEffect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEffectFactoryWithProperties(void* graphicsEffect, void* animatableProperties, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEffectFactory, WINRT_WRAP(Windows::UI::Composition::CompositionEffectFactory), Windows::Graphics::Effects::IGraphicsEffect const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::UI::Composition::CompositionEffectFactory>(this->shim().CreateEffectFactory(*reinterpret_cast<Windows::Graphics::Effects::IGraphicsEffect const*>(&graphicsEffect), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&animatableProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateExpressionAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateExpressionAnimation, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *result = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().CreateExpressionAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateExpressionAnimationWithExpression(void* expression, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateExpressionAnimation, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation), hstring const&);
            *result = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().CreateExpressionAnimation(*reinterpret_cast<hstring const*>(&expression)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInsetClip(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInsetClip, WINRT_WRAP(Windows::UI::Composition::InsetClip));
            *result = detach_from<Windows::UI::Composition::InsetClip>(this->shim().CreateInsetClip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInsetClipWithInsets(float leftInset, float topInset, float rightInset, float bottomInset, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInsetClip, WINRT_WRAP(Windows::UI::Composition::InsetClip), float, float, float, float);
            *result = detach_from<Windows::UI::Composition::InsetClip>(this->shim().CreateInsetClip(leftInset, topInset, rightInset, bottomInset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLinearEasingFunction(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLinearEasingFunction, WINRT_WRAP(Windows::UI::Composition::LinearEasingFunction));
            *result = detach_from<Windows::UI::Composition::LinearEasingFunction>(this->shim().CreateLinearEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePropertySet(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePropertySet, WINRT_WRAP(Windows::UI::Composition::CompositionPropertySet));
            *result = detach_from<Windows::UI::Composition::CompositionPropertySet>(this->shim().CreatePropertySet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateQuaternionKeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateQuaternionKeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::QuaternionKeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::QuaternionKeyFrameAnimation>(this->shim().CreateQuaternionKeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateScalarKeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScalarKeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::ScalarKeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::ScalarKeyFrameAnimation>(this->shim().CreateScalarKeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateScopedBatch(Windows::UI::Composition::CompositionBatchTypes batchType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScopedBatch, WINRT_WRAP(Windows::UI::Composition::CompositionScopedBatch), Windows::UI::Composition::CompositionBatchTypes const&);
            *result = detach_from<Windows::UI::Composition::CompositionScopedBatch>(this->shim().CreateScopedBatch(*reinterpret_cast<Windows::UI::Composition::CompositionBatchTypes const*>(&batchType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpriteVisual(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpriteVisual, WINRT_WRAP(Windows::UI::Composition::SpriteVisual));
            *result = detach_from<Windows::UI::Composition::SpriteVisual>(this->shim().CreateSpriteVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSurfaceBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSurfaceBrush, WINRT_WRAP(Windows::UI::Composition::CompositionSurfaceBrush));
            *result = detach_from<Windows::UI::Composition::CompositionSurfaceBrush>(this->shim().CreateSurfaceBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSurfaceBrushWithSurface(void* surface, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSurfaceBrush, WINRT_WRAP(Windows::UI::Composition::CompositionSurfaceBrush), Windows::UI::Composition::ICompositionSurface const&);
            *result = detach_from<Windows::UI::Composition::CompositionSurfaceBrush>(this->shim().CreateSurfaceBrush(*reinterpret_cast<Windows::UI::Composition::ICompositionSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTargetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTargetForCurrentView, WINRT_WRAP(Windows::UI::Composition::CompositionTarget));
            *result = detach_from<Windows::UI::Composition::CompositionTarget>(this->shim().CreateTargetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVector2KeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVector2KeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::Vector2KeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::Vector2KeyFrameAnimation>(this->shim().CreateVector2KeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVector3KeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVector3KeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::Vector3KeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::Vector3KeyFrameAnimation>(this->shim().CreateVector3KeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVector4KeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVector4KeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::Vector4KeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::Vector4KeyFrameAnimation>(this->shim().CreateVector4KeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCommitBatch(Windows::UI::Composition::CompositionBatchTypes batchType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCommitBatch, WINRT_WRAP(Windows::UI::Composition::CompositionCommitBatch), Windows::UI::Composition::CompositionBatchTypes const&);
            *result = detach_from<Windows::UI::Composition::CompositionCommitBatch>(this->shim().GetCommitBatch(*reinterpret_cast<Windows::UI::Composition::CompositionBatchTypes const*>(&batchType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor2> : produce_base<D, Windows::UI::Composition::ICompositor2>
{
    int32_t WINRT_CALL CreateAmbientLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAmbientLight, WINRT_WRAP(Windows::UI::Composition::AmbientLight));
            *result = detach_from<Windows::UI::Composition::AmbientLight>(this->shim().CreateAmbientLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAnimationGroup(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAnimationGroup, WINRT_WRAP(Windows::UI::Composition::CompositionAnimationGroup));
            *result = detach_from<Windows::UI::Composition::CompositionAnimationGroup>(this->shim().CreateAnimationGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBackdropBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBackdropBrush, WINRT_WRAP(Windows::UI::Composition::CompositionBackdropBrush));
            *result = detach_from<Windows::UI::Composition::CompositionBackdropBrush>(this->shim().CreateBackdropBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDistantLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDistantLight, WINRT_WRAP(Windows::UI::Composition::DistantLight));
            *result = detach_from<Windows::UI::Composition::DistantLight>(this->shim().CreateDistantLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDropShadow(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDropShadow, WINRT_WRAP(Windows::UI::Composition::DropShadow));
            *result = detach_from<Windows::UI::Composition::DropShadow>(this->shim().CreateDropShadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateImplicitAnimationCollection(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateImplicitAnimationCollection, WINRT_WRAP(Windows::UI::Composition::ImplicitAnimationCollection));
            *result = detach_from<Windows::UI::Composition::ImplicitAnimationCollection>(this->shim().CreateImplicitAnimationCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLayerVisual(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLayerVisual, WINRT_WRAP(Windows::UI::Composition::LayerVisual));
            *result = detach_from<Windows::UI::Composition::LayerVisual>(this->shim().CreateLayerVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMaskBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMaskBrush, WINRT_WRAP(Windows::UI::Composition::CompositionMaskBrush));
            *result = detach_from<Windows::UI::Composition::CompositionMaskBrush>(this->shim().CreateMaskBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateNineGridBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNineGridBrush, WINRT_WRAP(Windows::UI::Composition::CompositionNineGridBrush));
            *result = detach_from<Windows::UI::Composition::CompositionNineGridBrush>(this->shim().CreateNineGridBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePointLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePointLight, WINRT_WRAP(Windows::UI::Composition::PointLight));
            *result = detach_from<Windows::UI::Composition::PointLight>(this->shim().CreatePointLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpotLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpotLight, WINRT_WRAP(Windows::UI::Composition::SpotLight));
            *result = detach_from<Windows::UI::Composition::SpotLight>(this->shim().CreateSpotLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStepEasingFunction(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStepEasingFunction, WINRT_WRAP(Windows::UI::Composition::StepEasingFunction));
            *result = detach_from<Windows::UI::Composition::StepEasingFunction>(this->shim().CreateStepEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStepEasingFunctionWithStepCount(int32_t stepCount, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStepEasingFunction, WINRT_WRAP(Windows::UI::Composition::StepEasingFunction), int32_t);
            *result = detach_from<Windows::UI::Composition::StepEasingFunction>(this->shim().CreateStepEasingFunction(stepCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor3> : produce_base<D, Windows::UI::Composition::ICompositor3>
{
    int32_t WINRT_CALL CreateHostBackdropBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateHostBackdropBrush, WINRT_WRAP(Windows::UI::Composition::CompositionBackdropBrush));
            *result = detach_from<Windows::UI::Composition::CompositionBackdropBrush>(this->shim().CreateHostBackdropBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor4> : produce_base<D, Windows::UI::Composition::ICompositor4>
{
    int32_t WINRT_CALL CreateColorGradientStop(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateColorGradientStop, WINRT_WRAP(Windows::UI::Composition::CompositionColorGradientStop));
            *result = detach_from<Windows::UI::Composition::CompositionColorGradientStop>(this->shim().CreateColorGradientStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateColorGradientStopWithOffsetAndColor(float offset, struct struct_Windows_UI_Color color, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateColorGradientStop, WINRT_WRAP(Windows::UI::Composition::CompositionColorGradientStop), float, Windows::UI::Color const&);
            *result = detach_from<Windows::UI::Composition::CompositionColorGradientStop>(this->shim().CreateColorGradientStop(offset, *reinterpret_cast<Windows::UI::Color const*>(&color)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLinearGradientBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLinearGradientBrush, WINRT_WRAP(Windows::UI::Composition::CompositionLinearGradientBrush));
            *result = detach_from<Windows::UI::Composition::CompositionLinearGradientBrush>(this->shim().CreateLinearGradientBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpringScalarAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpringScalarAnimation, WINRT_WRAP(Windows::UI::Composition::SpringScalarNaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::SpringScalarNaturalMotionAnimation>(this->shim().CreateSpringScalarAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpringVector2Animation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpringVector2Animation, WINRT_WRAP(Windows::UI::Composition::SpringVector2NaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::SpringVector2NaturalMotionAnimation>(this->shim().CreateSpringVector2Animation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpringVector3Animation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpringVector3Animation, WINRT_WRAP(Windows::UI::Composition::SpringVector3NaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::SpringVector3NaturalMotionAnimation>(this->shim().CreateSpringVector3Animation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor5> : produce_base<D, Windows::UI::Composition::ICompositor5>
{
    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Comment(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(void), hstring const&);
            this->shim().Comment(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlobalPlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalPlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().GlobalPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GlobalPlaybackRate(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlobalPlaybackRate, WINRT_WRAP(void), float);
            this->shim().GlobalPlaybackRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBounceScalarAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBounceScalarAnimation, WINRT_WRAP(Windows::UI::Composition::BounceScalarNaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::BounceScalarNaturalMotionAnimation>(this->shim().CreateBounceScalarAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBounceVector2Animation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBounceVector2Animation, WINRT_WRAP(Windows::UI::Composition::BounceVector2NaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::BounceVector2NaturalMotionAnimation>(this->shim().CreateBounceVector2Animation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBounceVector3Animation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBounceVector3Animation, WINRT_WRAP(Windows::UI::Composition::BounceVector3NaturalMotionAnimation));
            *result = detach_from<Windows::UI::Composition::BounceVector3NaturalMotionAnimation>(this->shim().CreateBounceVector3Animation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateContainerShape(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateContainerShape, WINRT_WRAP(Windows::UI::Composition::CompositionContainerShape));
            *result = detach_from<Windows::UI::Composition::CompositionContainerShape>(this->shim().CreateContainerShape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEllipseGeometry(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEllipseGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionEllipseGeometry));
            *result = detach_from<Windows::UI::Composition::CompositionEllipseGeometry>(this->shim().CreateEllipseGeometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLineGeometry(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLineGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionLineGeometry));
            *result = detach_from<Windows::UI::Composition::CompositionLineGeometry>(this->shim().CreateLineGeometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePathGeometry(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePathGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionPathGeometry));
            *result = detach_from<Windows::UI::Composition::CompositionPathGeometry>(this->shim().CreatePathGeometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePathGeometryWithPath(void* path, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePathGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionPathGeometry), Windows::UI::Composition::CompositionPath const&);
            *result = detach_from<Windows::UI::Composition::CompositionPathGeometry>(this->shim().CreatePathGeometry(*reinterpret_cast<Windows::UI::Composition::CompositionPath const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePathKeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePathKeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::PathKeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::PathKeyFrameAnimation>(this->shim().CreatePathKeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRectangleGeometry(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRectangleGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionRectangleGeometry));
            *result = detach_from<Windows::UI::Composition::CompositionRectangleGeometry>(this->shim().CreateRectangleGeometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRoundedRectangleGeometry(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRoundedRectangleGeometry, WINRT_WRAP(Windows::UI::Composition::CompositionRoundedRectangleGeometry));
            *result = detach_from<Windows::UI::Composition::CompositionRoundedRectangleGeometry>(this->shim().CreateRoundedRectangleGeometry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateShapeVisual(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateShapeVisual, WINRT_WRAP(Windows::UI::Composition::ShapeVisual));
            *result = detach_from<Windows::UI::Composition::ShapeVisual>(this->shim().CreateShapeVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpriteShape(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpriteShape, WINRT_WRAP(Windows::UI::Composition::CompositionSpriteShape));
            *result = detach_from<Windows::UI::Composition::CompositionSpriteShape>(this->shim().CreateSpriteShape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSpriteShapeWithGeometry(void* geometry, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSpriteShape, WINRT_WRAP(Windows::UI::Composition::CompositionSpriteShape), Windows::UI::Composition::CompositionGeometry const&);
            *result = detach_from<Windows::UI::Composition::CompositionSpriteShape>(this->shim().CreateSpriteShape(*reinterpret_cast<Windows::UI::Composition::CompositionGeometry const*>(&geometry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateViewBox(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateViewBox, WINRT_WRAP(Windows::UI::Composition::CompositionViewBox));
            *result = detach_from<Windows::UI::Composition::CompositionViewBox>(this->shim().CreateViewBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCommitAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCommitAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RequestCommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositor6> : produce_base<D, Windows::UI::Composition::ICompositor6>
{
    int32_t WINRT_CALL CreateGeometricClip(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGeometricClip, WINRT_WRAP(Windows::UI::Composition::CompositionGeometricClip));
            *result = detach_from<Windows::UI::Composition::CompositionGeometricClip>(this->shim().CreateGeometricClip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateGeometricClipWithGeometry(void* geometry, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGeometricClip, WINRT_WRAP(Windows::UI::Composition::CompositionGeometricClip), Windows::UI::Composition::CompositionGeometry const&);
            *result = detach_from<Windows::UI::Composition::CompositionGeometricClip>(this->shim().CreateGeometricClip(*reinterpret_cast<Windows::UI::Composition::CompositionGeometry const*>(&geometry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRedirectVisual(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRedirectVisual, WINRT_WRAP(Windows::UI::Composition::RedirectVisual));
            *result = detach_from<Windows::UI::Composition::RedirectVisual>(this->shim().CreateRedirectVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateRedirectVisualWithSourceVisual(void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRedirectVisual, WINRT_WRAP(Windows::UI::Composition::RedirectVisual), Windows::UI::Composition::Visual const&);
            *result = detach_from<Windows::UI::Composition::RedirectVisual>(this->shim().CreateRedirectVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateBooleanKeyFrameAnimation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateBooleanKeyFrameAnimation, WINRT_WRAP(Windows::UI::Composition::BooleanKeyFrameAnimation));
            *result = detach_from<Windows::UI::Composition::BooleanKeyFrameAnimation>(this->shim().CreateBooleanKeyFrameAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositorStatics> : produce_base<D, Windows::UI::Composition::ICompositorStatics>
{
    int32_t WINRT_CALL get_MaxGlobalPlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxGlobalPlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxGlobalPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinGlobalPlaybackRate(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinGlobalPlaybackRate, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinGlobalPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositorWithProjectedShadow> : produce_base<D, Windows::UI::Composition::ICompositorWithProjectedShadow>
{
    int32_t WINRT_CALL CreateProjectedShadowCaster(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateProjectedShadowCaster, WINRT_WRAP(Windows::UI::Composition::CompositionProjectedShadowCaster));
            *result = detach_from<Windows::UI::Composition::CompositionProjectedShadowCaster>(this->shim().CreateProjectedShadowCaster());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateProjectedShadow(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateProjectedShadow, WINRT_WRAP(Windows::UI::Composition::CompositionProjectedShadow));
            *result = detach_from<Windows::UI::Composition::CompositionProjectedShadow>(this->shim().CreateProjectedShadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateProjectedShadowReceiver(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateProjectedShadowReceiver, WINRT_WRAP(Windows::UI::Composition::CompositionProjectedShadowReceiver));
            *result = detach_from<Windows::UI::Composition::CompositionProjectedShadowReceiver>(this->shim().CreateProjectedShadowReceiver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositorWithRadialGradient> : produce_base<D, Windows::UI::Composition::ICompositorWithRadialGradient>
{
    int32_t WINRT_CALL CreateRadialGradientBrush(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRadialGradientBrush, WINRT_WRAP(Windows::UI::Composition::CompositionRadialGradientBrush));
            *result = detach_from<Windows::UI::Composition::CompositionRadialGradientBrush>(this->shim().CreateRadialGradientBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ICompositorWithVisualSurface> : produce_base<D, Windows::UI::Composition::ICompositorWithVisualSurface>
{
    int32_t WINRT_CALL CreateVisualSurface(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVisualSurface, WINRT_WRAP(Windows::UI::Composition::CompositionVisualSurface));
            *result = detach_from<Windows::UI::Composition::CompositionVisualSurface>(this->shim().CreateVisualSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IContainerVisual> : produce_base<D, Windows::UI::Composition::IContainerVisual>
{
    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::UI::Composition::VisualCollection));
            *value = detach_from<Windows::UI::Composition::VisualCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IContainerVisualFactory> : produce_base<D, Windows::UI::Composition::IContainerVisualFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ICubicBezierEasingFunction> : produce_base<D, Windows::UI::Composition::ICubicBezierEasingFunction>
{
    int32_t WINRT_CALL get_ControlPoint1(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint1, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().ControlPoint1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlPoint2(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint2, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().ControlPoint2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IDistantLight> : produce_base<D, Windows::UI::Composition::IDistantLight>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSpace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().CoordinateSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CoordinateSpace(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().CoordinateSpace(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Direction(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Direction(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IDistantLight2> : produce_base<D, Windows::UI::Composition::IDistantLight2>
{
    int32_t WINRT_CALL get_Intensity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Intensity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Intensity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(void), float);
            this->shim().Intensity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IDropShadow> : produce_base<D, Windows::UI::Composition::IDropShadow>
{
    int32_t WINRT_CALL get_BlurRadius(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlurRadius, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BlurRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BlurRadius(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlurRadius, WINRT_WRAP(void), float);
            this->shim().BlurRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mask(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mask, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Mask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mask(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mask, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Mask(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Opacity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Opacity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(void), float);
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IDropShadow2> : produce_base<D, Windows::UI::Composition::IDropShadow2>
{
    int32_t WINRT_CALL get_SourcePolicy(Windows::UI::Composition::CompositionDropShadowSourcePolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePolicy, WINRT_WRAP(Windows::UI::Composition::CompositionDropShadowSourcePolicy));
            *value = detach_from<Windows::UI::Composition::CompositionDropShadowSourcePolicy>(this->shim().SourcePolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourcePolicy(Windows::UI::Composition::CompositionDropShadowSourcePolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePolicy, WINRT_WRAP(void), Windows::UI::Composition::CompositionDropShadowSourcePolicy const&);
            this->shim().SourcePolicy(*reinterpret_cast<Windows::UI::Composition::CompositionDropShadowSourcePolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IExpressionAnimation> : produce_base<D, Windows::UI::Composition::IExpressionAnimation>
{
    int32_t WINRT_CALL get_Expression(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expression, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Expression());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Expression(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expression, WINRT_WRAP(void), hstring const&);
            this->shim().Expression(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IImplicitAnimationCollection> : produce_base<D, Windows::UI::Composition::IImplicitAnimationCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IInsetClip> : produce_base<D, Windows::UI::Composition::IInsetClip>
{
    int32_t WINRT_CALL get_BottomInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BottomInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BottomInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomInset, WINRT_WRAP(void), float);
            this->shim().BottomInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LeftInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftInset, WINRT_WRAP(void), float);
            this->shim().LeftInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RightInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightInset, WINRT_WRAP(void), float);
            this->shim().RightInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TopInset(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInset, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TopInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TopInset(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopInset, WINRT_WRAP(void), float);
            this->shim().TopInset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IKeyFrameAnimation>
{
    int32_t WINRT_CALL get_DelayTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DelayTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DelayTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DelayTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
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

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IterationBehavior(Windows::UI::Composition::AnimationIterationBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IterationBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationIterationBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationIterationBehavior>(this->shim().IterationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IterationBehavior(Windows::UI::Composition::AnimationIterationBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IterationBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationIterationBehavior const&);
            this->shim().IterationBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationIterationBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IterationCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IterationCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().IterationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IterationCount(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IterationCount, WINRT_WRAP(void), int32_t);
            this->shim().IterationCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyFrameCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrameCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().KeyFrameCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StopBehavior(Windows::UI::Composition::AnimationStopBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationStopBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationStopBehavior>(this->shim().StopBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StopBehavior(Windows::UI::Composition::AnimationStopBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationStopBehavior const&);
            this->shim().StopBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationStopBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertExpressionKeyFrame(float normalizedProgressKey, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertExpressionKeyFrame, WINRT_WRAP(void), float, hstring const&);
            this->shim().InsertExpressionKeyFrame(normalizedProgressKey, *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertExpressionKeyFrameWithEasingFunction(float normalizedProgressKey, void* value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertExpressionKeyFrame, WINRT_WRAP(void), float, hstring const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertExpressionKeyFrame(normalizedProgressKey, *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IKeyFrameAnimation2> : produce_base<D, Windows::UI::Composition::IKeyFrameAnimation2>
{
    int32_t WINRT_CALL get_Direction(Windows::UI::Composition::AnimationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::Composition::AnimationDirection));
            *value = detach_from<Windows::UI::Composition::AnimationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Direction(Windows::UI::Composition::AnimationDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(void), Windows::UI::Composition::AnimationDirection const&);
            this->shim().Direction(*reinterpret_cast<Windows::UI::Composition::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IKeyFrameAnimation3> : produce_base<D, Windows::UI::Composition::IKeyFrameAnimation3>
{
    int32_t WINRT_CALL get_DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationDelayBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationDelayBehavior>(this->shim().DelayBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationDelayBehavior const&);
            this->shim().DelayBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationDelayBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IKeyFrameAnimationFactory> : produce_base<D, Windows::UI::Composition::IKeyFrameAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::ILayerVisual> : produce_base<D, Windows::UI::Composition::ILayerVisual>
{
    int32_t WINRT_CALL get_Effect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Effect, WINRT_WRAP(Windows::UI::Composition::CompositionEffectBrush));
            *value = detach_from<Windows::UI::Composition::CompositionEffectBrush>(this->shim().Effect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Effect(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Effect, WINRT_WRAP(void), Windows::UI::Composition::CompositionEffectBrush const&);
            this->shim().Effect(*reinterpret_cast<Windows::UI::Composition::CompositionEffectBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ILayerVisual2> : produce_base<D, Windows::UI::Composition::ILayerVisual2>
{
    int32_t WINRT_CALL get_Shadow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(Windows::UI::Composition::CompositionShadow));
            *value = detach_from<Windows::UI::Composition::CompositionShadow>(this->shim().Shadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Shadow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(void), Windows::UI::Composition::CompositionShadow const&);
            this->shim().Shadow(*reinterpret_cast<Windows::UI::Composition::CompositionShadow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ILinearEasingFunction> : produce_base<D, Windows::UI::Composition::ILinearEasingFunction>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::INaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::INaturalMotionAnimation>
{
    int32_t WINRT_CALL get_DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationDelayBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationDelayBehavior>(this->shim().DelayBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DelayBehavior(Windows::UI::Composition::AnimationDelayBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationDelayBehavior const&);
            this->shim().DelayBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationDelayBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DelayTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DelayTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DelayTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DelayTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DelayTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StopBehavior(Windows::UI::Composition::AnimationStopBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopBehavior, WINRT_WRAP(Windows::UI::Composition::AnimationStopBehavior));
            *value = detach_from<Windows::UI::Composition::AnimationStopBehavior>(this->shim().StopBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StopBehavior(Windows::UI::Composition::AnimationStopBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopBehavior, WINRT_WRAP(void), Windows::UI::Composition::AnimationStopBehavior const&);
            this->shim().StopBehavior(*reinterpret_cast<Windows::UI::Composition::AnimationStopBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::INaturalMotionAnimationFactory> : produce_base<D, Windows::UI::Composition::INaturalMotionAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IPathKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IPathKeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, void* path) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::UI::Composition::CompositionPath const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::UI::Composition::CompositionPath const*>(&path));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, void* path, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::UI::Composition::CompositionPath const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::UI::Composition::CompositionPath const*>(&path), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IPointLight> : produce_base<D, Windows::UI::Composition::IPointLight>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConstantAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConstantAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ConstantAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ConstantAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConstantAttenuation, WINRT_WRAP(void), float);
            this->shim().ConstantAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSpace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().CoordinateSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CoordinateSpace(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().CoordinateSpace(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinearAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinearAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LinearAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LinearAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinearAttenuation, WINRT_WRAP(void), float);
            this->shim().LinearAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QuadraticAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuadraticAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().QuadraticAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_QuadraticAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuadraticAttenuation, WINRT_WRAP(void), float);
            this->shim().QuadraticAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IPointLight2> : produce_base<D, Windows::UI::Composition::IPointLight2>
{
    int32_t WINRT_CALL get_Intensity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Intensity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Intensity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intensity, WINRT_WRAP(void), float);
            this->shim().Intensity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IPointLight3> : produce_base<D, Windows::UI::Composition::IPointLight3>
{
    int32_t WINRT_CALL get_MinAttenuationCutoff(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinAttenuationCutoff, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinAttenuationCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinAttenuationCutoff(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinAttenuationCutoff, WINRT_WRAP(void), float);
            this->shim().MinAttenuationCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAttenuationCutoff(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttenuationCutoff, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxAttenuationCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAttenuationCutoff(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttenuationCutoff, WINRT_WRAP(void), float);
            this->shim().MaxAttenuationCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IQuaternionKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IQuaternionKeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::quaternion const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, Windows::Foundation::Numerics::quaternion value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::quaternion const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IRedirectVisual> : produce_base<D, Windows::UI::Composition::IRedirectVisual>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Source(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IRenderingDeviceReplacedEventArgs> : produce_base<D, Windows::UI::Composition::IRenderingDeviceReplacedEventArgs>
{
    int32_t WINRT_CALL get_GraphicsDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GraphicsDevice, WINRT_WRAP(Windows::UI::Composition::CompositionGraphicsDevice));
            *value = detach_from<Windows::UI::Composition::CompositionGraphicsDevice>(this->shim().GraphicsDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IScalarKeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IScalarKeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, float);
            this->shim().InsertKeyFrame(normalizedProgressKey, value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, float value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, float, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, value, *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IScalarNaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IScalarNaturalMotionAnimation>
{
    int32_t WINRT_CALL get_FinalValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().FinalValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FinalValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(void), Windows::Foundation::IReference<float> const&);
            this->shim().FinalValue(*reinterpret_cast<Windows::Foundation::IReference<float> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().InitialValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(void), Windows::Foundation::IReference<float> const&);
            this->shim().InitialValue(*reinterpret_cast<Windows::Foundation::IReference<float> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialVelocity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InitialVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialVelocity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(void), float);
            this->shim().InitialVelocity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IScalarNaturalMotionAnimationFactory> : produce_base<D, Windows::UI::Composition::IScalarNaturalMotionAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IShapeVisual> : produce_base<D, Windows::UI::Composition::IShapeVisual>
{
    int32_t WINRT_CALL get_Shapes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shapes, WINRT_WRAP(Windows::UI::Composition::CompositionShapeCollection));
            *value = detach_from<Windows::UI::Composition::CompositionShapeCollection>(this->shim().Shapes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewBox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewBox, WINRT_WRAP(Windows::UI::Composition::CompositionViewBox));
            *value = detach_from<Windows::UI::Composition::CompositionViewBox>(this->shim().ViewBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewBox(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewBox, WINRT_WRAP(void), Windows::UI::Composition::CompositionViewBox const&);
            this->shim().ViewBox(*reinterpret_cast<Windows::UI::Composition::CompositionViewBox const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpotLight> : produce_base<D, Windows::UI::Composition::ISpotLight>
{
    int32_t WINRT_CALL get_ConstantAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConstantAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ConstantAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ConstantAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConstantAttenuation, WINRT_WRAP(void), float);
            this->shim().ConstantAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSpace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().CoordinateSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CoordinateSpace(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSpace, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().CoordinateSpace(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Direction(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Direction(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InnerConeAngle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeAngle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InnerConeAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InnerConeAngle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeAngle, WINRT_WRAP(void), float);
            this->shim().InnerConeAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InnerConeAngleInDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeAngleInDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InnerConeAngleInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InnerConeAngleInDegrees(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeAngleInDegrees, WINRT_WRAP(void), float);
            this->shim().InnerConeAngleInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InnerConeColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().InnerConeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InnerConeColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().InnerConeColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinearAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinearAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LinearAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LinearAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinearAttenuation, WINRT_WRAP(void), float);
            this->shim().LinearAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OuterConeAngle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeAngle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().OuterConeAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OuterConeAngle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeAngle, WINRT_WRAP(void), float);
            this->shim().OuterConeAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OuterConeAngleInDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeAngleInDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().OuterConeAngleInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OuterConeAngleInDegrees(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeAngleInDegrees, WINRT_WRAP(void), float);
            this->shim().OuterConeAngleInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OuterConeColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OuterConeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OuterConeColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().OuterConeColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QuadraticAttenuation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuadraticAttenuation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().QuadraticAttenuation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_QuadraticAttenuation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuadraticAttenuation, WINRT_WRAP(void), float);
            this->shim().QuadraticAttenuation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpotLight2> : produce_base<D, Windows::UI::Composition::ISpotLight2>
{
    int32_t WINRT_CALL get_InnerConeIntensity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeIntensity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InnerConeIntensity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InnerConeIntensity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InnerConeIntensity, WINRT_WRAP(void), float);
            this->shim().InnerConeIntensity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OuterConeIntensity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeIntensity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().OuterConeIntensity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OuterConeIntensity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OuterConeIntensity, WINRT_WRAP(void), float);
            this->shim().OuterConeIntensity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpotLight3> : produce_base<D, Windows::UI::Composition::ISpotLight3>
{
    int32_t WINRT_CALL get_MinAttenuationCutoff(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinAttenuationCutoff, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinAttenuationCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinAttenuationCutoff(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinAttenuationCutoff, WINRT_WRAP(void), float);
            this->shim().MinAttenuationCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAttenuationCutoff(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttenuationCutoff, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxAttenuationCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAttenuationCutoff(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttenuationCutoff, WINRT_WRAP(void), float);
            this->shim().MaxAttenuationCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpringScalarNaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::ISpringScalarNaturalMotionAnimation>
{
    int32_t WINRT_CALL get_DampingRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DampingRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DampingRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(void), float);
            this->shim().DampingRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Period(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Period(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Period(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpringVector2NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::ISpringVector2NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_DampingRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DampingRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DampingRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(void), float);
            this->shim().DampingRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Period(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Period(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Period(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpringVector3NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::ISpringVector3NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_DampingRatio(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DampingRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DampingRatio(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DampingRatio, WINRT_WRAP(void), float);
            this->shim().DampingRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Period(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Period());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Period(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Period, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Period(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpriteVisual> : produce_base<D, Windows::UI::Composition::ISpriteVisual>
{
    int32_t WINRT_CALL get_Brush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brush, WINRT_WRAP(Windows::UI::Composition::CompositionBrush));
            *value = detach_from<Windows::UI::Composition::CompositionBrush>(this->shim().Brush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Brush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brush, WINRT_WRAP(void), Windows::UI::Composition::CompositionBrush const&);
            this->shim().Brush(*reinterpret_cast<Windows::UI::Composition::CompositionBrush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::ISpriteVisual2> : produce_base<D, Windows::UI::Composition::ISpriteVisual2>
{
    int32_t WINRT_CALL get_Shadow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(Windows::UI::Composition::CompositionShadow));
            *value = detach_from<Windows::UI::Composition::CompositionShadow>(this->shim().Shadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Shadow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(void), Windows::UI::Composition::CompositionShadow const&);
            this->shim().Shadow(*reinterpret_cast<Windows::UI::Composition::CompositionShadow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IStepEasingFunction> : produce_base<D, Windows::UI::Composition::IStepEasingFunction>
{
    int32_t WINRT_CALL get_FinalStep(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalStep, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FinalStep());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FinalStep(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalStep, WINRT_WRAP(void), int32_t);
            this->shim().FinalStep(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialStep(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialStep, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().InitialStep());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialStep(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialStep, WINRT_WRAP(void), int32_t);
            this->shim().InitialStep(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFinalStepSingleFrame(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFinalStepSingleFrame, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFinalStepSingleFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsFinalStepSingleFrame(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFinalStepSingleFrame, WINRT_WRAP(void), bool);
            this->shim().IsFinalStepSingleFrame(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInitialStepSingleFrame(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInitialStepSingleFrame, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInitialStepSingleFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInitialStepSingleFrame(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInitialStepSingleFrame, WINRT_WRAP(void), bool);
            this->shim().IsInitialStepSingleFrame(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StepCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StepCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StepCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StepCount(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StepCount, WINRT_WRAP(void), int32_t);
            this->shim().StepCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector2KeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IVector2KeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float2 const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, Windows::Foundation::Numerics::float2 value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float2 const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector2NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IVector2NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_FinalValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float2>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float2>>(this->shim().FinalValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FinalValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> const&);
            this->shim().FinalValue(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float2>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float2>>(this->shim().InitialValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> const&);
            this->shim().InitialValue(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Numerics::float2> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialVelocity(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().InitialVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialVelocity(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().InitialVelocity(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector2NaturalMotionAnimationFactory> : produce_base<D, Windows::UI::Composition::IVector2NaturalMotionAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector3KeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IVector3KeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float3 const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, Windows::Foundation::Numerics::float3 value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float3 const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector3NaturalMotionAnimation> : produce_base<D, Windows::UI::Composition::IVector3NaturalMotionAnimation>
{
    int32_t WINRT_CALL get_FinalValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().FinalValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FinalValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalValue, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const&);
            this->shim().FinalValue(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().InitialValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialValue, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const&);
            this->shim().InitialValue(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialVelocity(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().InitialVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialVelocity(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialVelocity, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().InitialVelocity(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector3NaturalMotionAnimationFactory> : produce_base<D, Windows::UI::Composition::IVector3NaturalMotionAnimationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IVector4KeyFrameAnimation> : produce_base<D, Windows::UI::Composition::IVector4KeyFrameAnimation>
{
    int32_t WINRT_CALL InsertKeyFrame(float normalizedProgressKey, Windows::Foundation::Numerics::float4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float4 const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertKeyFrameWithEasingFunction(float normalizedProgressKey, Windows::Foundation::Numerics::float4 value, void* easingFunction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertKeyFrame, WINRT_WRAP(void), float, Windows::Foundation::Numerics::float4 const&, Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().InsertKeyFrame(normalizedProgressKey, *reinterpret_cast<Windows::Foundation::Numerics::float4 const*>(&value), *reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&easingFunction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisual> : produce_base<D, Windows::UI::Composition::IVisual>
{
    int32_t WINRT_CALL get_AnchorPoint(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().AnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnchorPoint(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnchorPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().AnchorPoint(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackfaceVisibility(Windows::UI::Composition::CompositionBackfaceVisibility* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackfaceVisibility, WINRT_WRAP(Windows::UI::Composition::CompositionBackfaceVisibility));
            *value = detach_from<Windows::UI::Composition::CompositionBackfaceVisibility>(this->shim().BackfaceVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackfaceVisibility(Windows::UI::Composition::CompositionBackfaceVisibility value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackfaceVisibility, WINRT_WRAP(void), Windows::UI::Composition::CompositionBackfaceVisibility const&);
            this->shim().BackfaceVisibility(*reinterpret_cast<Windows::UI::Composition::CompositionBackfaceVisibility const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BorderMode(Windows::UI::Composition::CompositionBorderMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BorderMode, WINRT_WRAP(Windows::UI::Composition::CompositionBorderMode));
            *value = detach_from<Windows::UI::Composition::CompositionBorderMode>(this->shim().BorderMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BorderMode(Windows::UI::Composition::CompositionBorderMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BorderMode, WINRT_WRAP(void), Windows::UI::Composition::CompositionBorderMode const&);
            this->shim().BorderMode(*reinterpret_cast<Windows::UI::Composition::CompositionBorderMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clip(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clip, WINRT_WRAP(Windows::UI::Composition::CompositionClip));
            *value = detach_from<Windows::UI::Composition::CompositionClip>(this->shim().Clip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Clip(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clip, WINRT_WRAP(void), Windows::UI::Composition::CompositionClip const&);
            this->shim().Clip(*reinterpret_cast<Windows::UI::Composition::CompositionClip const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompositeMode(Windows::UI::Composition::CompositionCompositeMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeMode, WINRT_WRAP(Windows::UI::Composition::CompositionCompositeMode));
            *value = detach_from<Windows::UI::Composition::CompositionCompositeMode>(this->shim().CompositeMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompositeMode(Windows::UI::Composition::CompositionCompositeMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeMode, WINRT_WRAP(void), Windows::UI::Composition::CompositionCompositeMode const&);
            this->shim().CompositeMode(*reinterpret_cast<Windows::UI::Composition::CompositionCompositeMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(void), bool);
            this->shim().IsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Offset(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Offset(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Opacity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Opacity(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(void), float);
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Composition::ContainerVisual));
            *value = detach_from<Windows::UI::Composition::ContainerVisual>(this->shim().Parent());
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

    int32_t WINRT_CALL get_Size(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().Size(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float4x4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float4x4 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisual2> : produce_base<D, Windows::UI::Composition::IVisual2>
{
    int32_t WINRT_CALL get_ParentForTransform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentForTransform, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().ParentForTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ParentForTransform(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentForTransform, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().ParentForTransform(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeOffsetAdjustment(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeOffsetAdjustment, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().RelativeOffsetAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeOffsetAdjustment(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeOffsetAdjustment, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().RelativeOffsetAdjustment(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeSizeAdjustment(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeSizeAdjustment, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().RelativeSizeAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeSizeAdjustment(Windows::Foundation::Numerics::float2 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeSizeAdjustment, WINRT_WRAP(void), Windows::Foundation::Numerics::float2 const&);
            this->shim().RelativeSizeAdjustment(*reinterpret_cast<Windows::Foundation::Numerics::float2 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisualCollection> : produce_base<D, Windows::UI::Composition::IVisualCollection>
{
    int32_t WINRT_CALL get_Count(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Count, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAbove(void* newChild, void* sibling) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAbove, WINRT_WRAP(void), Windows::UI::Composition::Visual const&, Windows::UI::Composition::Visual const&);
            this->shim().InsertAbove(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&newChild), *reinterpret_cast<Windows::UI::Composition::Visual const*>(&sibling));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAtBottom(void* newChild) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAtBottom, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().InsertAtBottom(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&newChild));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertAtTop(void* newChild) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertAtTop, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().InsertAtTop(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&newChild));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertBelow(void* newChild, void* sibling) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertBelow, WINRT_WRAP(void), Windows::UI::Composition::Visual const&, Windows::UI::Composition::Visual const&);
            this->shim().InsertBelow(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&newChild), *reinterpret_cast<Windows::UI::Composition::Visual const*>(&sibling));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* child) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&child));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAll, WINRT_WRAP(void));
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisualElement> : produce_base<D, Windows::UI::Composition::IVisualElement>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisualFactory> : produce_base<D, Windows::UI::Composition::IVisualFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::IVisualUnorderedCollection> : produce_base<D, Windows::UI::Composition::IVisualUnorderedCollection>
{
    int32_t WINRT_CALL get_Count(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Count, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Count());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Add(void* newVisual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Add(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&newVisual));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* visual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::Visual const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&visual));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAll, WINRT_WRAP(void));
            this->shim().RemoveAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

inline float AnimationController::MaxPlaybackRate()
{
    return impl::call_factory<AnimationController, Windows::UI::Composition::IAnimationControllerStatics>([&](auto&& f) { return f.MaxPlaybackRate(); });
}

inline float AnimationController::MinPlaybackRate()
{
    return impl::call_factory<AnimationController, Windows::UI::Composition::IAnimationControllerStatics>([&](auto&& f) { return f.MinPlaybackRate(); });
}

inline Windows::UI::Composition::CompositionCapabilities CompositionCapabilities::GetForCurrentView()
{
    return impl::call_factory<CompositionCapabilities, Windows::UI::Composition::ICompositionCapabilitiesStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline CompositionEffectSourceParameter::CompositionEffectSourceParameter(param::hstring const& name) :
    CompositionEffectSourceParameter(impl::call_factory<CompositionEffectSourceParameter, Windows::UI::Composition::ICompositionEffectSourceParameterFactory>([&](auto&& f) { return f.Create(name); }))
{}

inline void CompositionObject::StartAnimationWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, param::hstring const& propertyName, Windows::UI::Composition::CompositionAnimation const& animation)
{
    impl::call_factory<CompositionObject, Windows::UI::Composition::ICompositionObjectStatics>([&](auto&& f) { return f.StartAnimationWithIAnimationObject(target, propertyName, animation); });
}

inline void CompositionObject::StartAnimationGroupWithIAnimationObject(Windows::UI::Composition::IAnimationObject const& target, Windows::UI::Composition::ICompositionAnimationBase const& animation)
{
    impl::call_factory<CompositionObject, Windows::UI::Composition::ICompositionObjectStatics>([&](auto&& f) { return f.StartAnimationGroupWithIAnimationObject(target, animation); });
}

inline CompositionPath::CompositionPath(Windows::Graphics::IGeometrySource2D const& source) :
    CompositionPath(impl::call_factory<CompositionPath, Windows::UI::Composition::ICompositionPathFactory>([&](auto&& f) { return f.Create(source); }))
{}

inline int32_t CompositionProjectedShadowCasterCollection::MaxRespectedCasters()
{
    return impl::call_factory<CompositionProjectedShadowCasterCollection, Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics>([&](auto&& f) { return f.MaxRespectedCasters(); });
}

inline Compositor::Compositor() :
    Compositor(impl::call_factory<Compositor>([](auto&& f) { return f.template ActivateInstance<Compositor>(); }))
{}

inline float Compositor::MaxGlobalPlaybackRate()
{
    return impl::call_factory<Compositor, Windows::UI::Composition::ICompositorStatics>([&](auto&& f) { return f.MaxGlobalPlaybackRate(); });
}

inline float Compositor::MinGlobalPlaybackRate()
{
    return impl::call_factory<Compositor, Windows::UI::Composition::ICompositorStatics>([&](auto&& f) { return f.MinGlobalPlaybackRate(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::IAmbientLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAmbientLight> {};
template<> struct hash<winrt::Windows::UI::Composition::IAmbientLight2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAmbientLight2> {};
template<> struct hash<winrt::Windows::UI::Composition::IAnimationController> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAnimationController> {};
template<> struct hash<winrt::Windows::UI::Composition::IAnimationControllerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAnimationControllerStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::IAnimationObject> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAnimationObject> {};
template<> struct hash<winrt::Windows::UI::Composition::IAnimationPropertyInfo> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IAnimationPropertyInfo> {};
template<> struct hash<winrt::Windows::UI::Composition::IBooleanKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IBooleanKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IBounceScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IBounceScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IBounceVector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IBounceVector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IBounceVector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IBounceVector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IColorKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IColorKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimation2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimation2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimation3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimation3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimation4> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimation4> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimationBase> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimationBase> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionAnimationGroup> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionAnimationGroup> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionBackdropBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionBackdropBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionBatchCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionBatchCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionCapabilities> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionCapabilities> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionCapabilitiesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionCapabilitiesStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionClip> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionClip2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionClip2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionClipFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionClipFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionColorBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionColorBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionColorGradientStop> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionColorGradientStop> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionColorGradientStopCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionColorGradientStopCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionCommitBatch> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionCommitBatch> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionContainerShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionContainerShape> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionDrawingSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionDrawingSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionDrawingSurface2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionDrawingSurface2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionDrawingSurfaceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionDrawingSurfaceFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEasingFunctionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEasingFunctionFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEffectBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEffectBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEffectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEffectFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEffectSourceParameter> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEffectSourceParameter> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEffectSourceParameterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEffectSourceParameterFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionEllipseGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionEllipseGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGeometricClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGeometricClip> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGeometryFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGeometryFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGradientBrush2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGradientBrush2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGradientBrushFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGradientBrushFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGraphicsDevice> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGraphicsDevice> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGraphicsDevice2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGraphicsDevice2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionGraphicsDevice3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionGraphicsDevice3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLight> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLight2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLight2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLight3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLight3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLightFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLightFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLineGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLineGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionLinearGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionLinearGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionMaskBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionMaskBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionMipmapSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionMipmapSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionNineGridBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionNineGridBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObject> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObject> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObject2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObject2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObject3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObject3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObject4> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObject4> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObjectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObjectFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionObjectStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionObjectStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionPath> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionPath> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionPathFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionPathFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionPathGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionPathGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadowCaster> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadowCaster> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadowCasterCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadowCasterCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadowCasterCollectionStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadowReceiver> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadowReceiver> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionProjectedShadowReceiverUnorderedCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionPropertySet> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionPropertySet> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionPropertySet2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionPropertySet2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionRadialGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionRadialGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionRectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionRectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionRoundedRectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionRoundedRectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionScopedBatch> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionScopedBatch> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionShadowFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionShadowFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionShape> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionShapeFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionShapeFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionSpriteShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionSpriteShape> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionSurfaceBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionSurfaceBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionSurfaceBrush2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionSurfaceBrush2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionSurfaceBrush3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionSurfaceBrush3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionTarget> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionTarget> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionTargetFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionTargetFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionTransform> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionTransform> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionTransformFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionTransformFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionViewBox> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionViewBox> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionVirtualDrawingSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionVirtualDrawingSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionVirtualDrawingSurfaceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionVirtualDrawingSurfaceFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositionVisualSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositionVisualSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor2> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor3> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor4> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor4> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor5> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor5> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositor6> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositor6> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositorStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositorWithProjectedShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositorWithProjectedShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositorWithRadialGradient> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositorWithRadialGradient> {};
template<> struct hash<winrt::Windows::UI::Composition::ICompositorWithVisualSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICompositorWithVisualSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::IContainerVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IContainerVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::IContainerVisualFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IContainerVisualFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ICubicBezierEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ICubicBezierEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::IDistantLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IDistantLight> {};
template<> struct hash<winrt::Windows::UI::Composition::IDistantLight2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IDistantLight2> {};
template<> struct hash<winrt::Windows::UI::Composition::IDropShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IDropShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::IDropShadow2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IDropShadow2> {};
template<> struct hash<winrt::Windows::UI::Composition::IExpressionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IExpressionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IImplicitAnimationCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IImplicitAnimationCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::IInsetClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IInsetClip> {};
template<> struct hash<winrt::Windows::UI::Composition::IKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IKeyFrameAnimation2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IKeyFrameAnimation2> {};
template<> struct hash<winrt::Windows::UI::Composition::IKeyFrameAnimation3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IKeyFrameAnimation3> {};
template<> struct hash<winrt::Windows::UI::Composition::IKeyFrameAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IKeyFrameAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::ILayerVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ILayerVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::ILayerVisual2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ILayerVisual2> {};
template<> struct hash<winrt::Windows::UI::Composition::ILinearEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ILinearEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::INaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::INaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::INaturalMotionAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::INaturalMotionAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::IPathKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IPathKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IPointLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IPointLight> {};
template<> struct hash<winrt::Windows::UI::Composition::IPointLight2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IPointLight2> {};
template<> struct hash<winrt::Windows::UI::Composition::IPointLight3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IPointLight3> {};
template<> struct hash<winrt::Windows::UI::Composition::IQuaternionKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IQuaternionKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IRedirectVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IRedirectVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::IRenderingDeviceReplacedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IRenderingDeviceReplacedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::IScalarKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IScalarKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IScalarNaturalMotionAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IScalarNaturalMotionAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::IShapeVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IShapeVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpotLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpotLight> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpotLight2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpotLight2> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpotLight3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpotLight3> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpringScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpringScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpringVector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpringVector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpringVector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpringVector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpriteVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpriteVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::ISpriteVisual2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ISpriteVisual2> {};
template<> struct hash<winrt::Windows::UI::Composition::IStepEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IStepEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector2KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector2KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector2NaturalMotionAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector2NaturalMotionAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector3KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector3KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector3NaturalMotionAnimationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector3NaturalMotionAnimationFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::IVector4KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVector4KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisual2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisual2> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisualCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisualCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisualElement> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisualElement> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisualFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisualFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::IVisualUnorderedCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::IVisualUnorderedCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::AmbientLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::AmbientLight> {};
template<> struct hash<winrt::Windows::UI::Composition::AnimationController> : winrt::impl::hash_base<winrt::Windows::UI::Composition::AnimationController> {};
template<> struct hash<winrt::Windows::UI::Composition::AnimationPropertyInfo> : winrt::impl::hash_base<winrt::Windows::UI::Composition::AnimationPropertyInfo> {};
template<> struct hash<winrt::Windows::UI::Composition::BooleanKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::BooleanKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::BounceScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::BounceScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::BounceVector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::BounceVector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::BounceVector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::BounceVector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ColorKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ColorKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionAnimationGroup> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionAnimationGroup> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionBackdropBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionBackdropBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionBatchCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionBatchCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionCapabilities> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionCapabilities> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionClip> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionColorBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionColorBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionColorGradientStop> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionColorGradientStop> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionColorGradientStopCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionColorGradientStopCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionCommitBatch> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionCommitBatch> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionContainerShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionContainerShape> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionDrawingSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionDrawingSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionEffectBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionEffectBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionEffectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionEffectFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionEffectSourceParameter> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionEffectSourceParameter> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionEllipseGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionEllipseGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionGeometricClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionGeometricClip> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionGraphicsDevice> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionGraphicsDevice> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionLight> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionLineGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionLineGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionLinearGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionLinearGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionMaskBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionMaskBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionMipmapSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionMipmapSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionNineGridBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionNineGridBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionObject> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionObject> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionPath> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionPath> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionPathGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionPathGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionProjectedShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionProjectedShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionProjectedShadowCaster> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionProjectedShadowCaster> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionProjectedShadowCasterCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionProjectedShadowCasterCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionProjectedShadowReceiver> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionProjectedShadowReceiver> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionProjectedShadowReceiverUnorderedCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionPropertySet> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionPropertySet> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionRadialGradientBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionRadialGradientBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionRectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionRectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionRoundedRectangleGeometry> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionRoundedRectangleGeometry> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionScopedBatch> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionScopedBatch> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionShape> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionShapeCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionShapeCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionSpriteShape> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionSpriteShape> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionStrokeDashArray> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionStrokeDashArray> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionSurfaceBrush> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionSurfaceBrush> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionTarget> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionTarget> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionTransform> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionTransform> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionViewBox> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionViewBox> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionVirtualDrawingSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionVirtualDrawingSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::CompositionVisualSurface> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CompositionVisualSurface> {};
template<> struct hash<winrt::Windows::UI::Composition::Compositor> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Compositor> {};
template<> struct hash<winrt::Windows::UI::Composition::ContainerVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ContainerVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::CubicBezierEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::CubicBezierEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::DistantLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::DistantLight> {};
template<> struct hash<winrt::Windows::UI::Composition::DropShadow> : winrt::impl::hash_base<winrt::Windows::UI::Composition::DropShadow> {};
template<> struct hash<winrt::Windows::UI::Composition::ExpressionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ExpressionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ImplicitAnimationCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ImplicitAnimationCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::InitialValueExpressionCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::InitialValueExpressionCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::InsetClip> : winrt::impl::hash_base<winrt::Windows::UI::Composition::InsetClip> {};
template<> struct hash<winrt::Windows::UI::Composition::KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::LayerVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::LayerVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::LinearEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::LinearEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::PathKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::PathKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::PointLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::PointLight> {};
template<> struct hash<winrt::Windows::UI::Composition::QuaternionKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::QuaternionKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::RedirectVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::RedirectVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::RenderingDeviceReplacedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::RenderingDeviceReplacedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::ScalarKeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ScalarKeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::ShapeVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::ShapeVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::SpotLight> : winrt::impl::hash_base<winrt::Windows::UI::Composition::SpotLight> {};
template<> struct hash<winrt::Windows::UI::Composition::SpringScalarNaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::SpringScalarNaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::SpringVector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::SpringVector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::SpringVector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::SpringVector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::SpriteVisual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::SpriteVisual> {};
template<> struct hash<winrt::Windows::UI::Composition::StepEasingFunction> : winrt::impl::hash_base<winrt::Windows::UI::Composition::StepEasingFunction> {};
template<> struct hash<winrt::Windows::UI::Composition::Vector2KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Vector2KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Vector2NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::Vector3KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Vector3KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::Vector3NaturalMotionAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Vector3NaturalMotionAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::Vector4KeyFrameAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Vector4KeyFrameAnimation> {};
template<> struct hash<winrt::Windows::UI::Composition::Visual> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Visual> {};
template<> struct hash<winrt::Windows::UI::Composition::VisualCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::VisualCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::VisualUnorderedCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::VisualUnorderedCollection> {};

}
