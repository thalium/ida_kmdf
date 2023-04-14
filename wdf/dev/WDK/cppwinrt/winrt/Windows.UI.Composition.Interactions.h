// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Composition.Interactions.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Condition() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionConditionalValue)->get_Condition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Condition(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionConditionalValue)->put_Condition(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Value() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionConditionalValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_ICompositionConditionalValue<D>::Value(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionConditionalValue)->put_Value(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::CompositionConditionalValue consume_Windows_UI_Composition_Interactions_ICompositionConditionalValueStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::CompositionConditionalValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Count() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->get_Count(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Add(Windows::UI::Composition::Interactions::ICompositionInteractionSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->Add(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::Remove(Windows::UI::Composition::Interactions::ICompositionInteractionSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->Remove(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection<D>::RemoveAll() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection)->RemoveAll());
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionXSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_PositionXSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_PositionXSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionYSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_PositionYSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_PositionYSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::ScaleSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->get_ScaleSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration<D>::ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionSourceConfiguration)->put_ScaleSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::InteractionSources() const
{
    Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_InteractionSources(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::IsPositionRoundingSuggested() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_IsPositionRoundingSuggested(&value));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxPosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_MaxPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxPosition(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_MaxPosition(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_MaxScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MaxScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_MaxScale(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinPosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_MinPosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinPosition(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_MinPosition(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_MinScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::MinScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_MinScale(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::NaturalRestingPosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_NaturalRestingPosition(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::NaturalRestingScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_NaturalRestingScale(&value));
    return value;
}

template <typename D> Windows::UI::Composition::Interactions::IInteractionTrackerOwner consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Owner() const
{
    Windows::UI::Composition::Interactions::IInteractionTrackerOwner value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_Owner(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionInertiaDecayRate() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_PositionInertiaDecayRate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionInertiaDecayRate(optional<Windows::Foundation::Numerics::float3> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_PositionInertiaDecayRate(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::PositionVelocityInPixelsPerSecond() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_PositionVelocityInPixelsPerSecond(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::Scale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_Scale(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleInertiaDecayRate() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_ScaleInertiaDecayRate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleInertiaDecayRate(optional<float> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->put_ScaleInertiaDecayRate(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ScaleVelocityInPercentPerSecond() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->get_ScaleVelocityInPercentPerSecond(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::AdjustPositionXIfGreaterThanThreshold(float adjustment, float positionThreshold) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->AdjustPositionXIfGreaterThanThreshold(adjustment, positionThreshold));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::AdjustPositionYIfGreaterThanThreshold(float adjustment, float positionThreshold) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->AdjustPositionYIfGreaterThanThreshold(adjustment, positionThreshold));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigurePositionXInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigurePositionXInertiaModifiers(get_abi(modifiers)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigurePositionYInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigurePositionYInertiaModifiers(get_abi(modifiers)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::ConfigureScaleInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const& modifiers) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->ConfigureScaleInertiaModifiers(get_abi(modifiers)));
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePosition(Windows::Foundation::Numerics::float3 const& value) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePosition(get_abi(value), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionBy(Windows::Foundation::Numerics::float3 const& amount) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionBy(get_abi(amount), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionWithAnimation(Windows::UI::Composition::CompositionAnimation const& animation) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionWithAnimation(get_abi(animation), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdatePositionWithAdditionalVelocity(Windows::Foundation::Numerics::float3 const& velocityInPixelsPerSecond) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdatePositionWithAdditionalVelocity(get_abi(velocityInPixelsPerSecond), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScale(float value, Windows::Foundation::Numerics::float3 const& centerPoint) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScale(value, get_abi(centerPoint), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScaleWithAnimation(Windows::UI::Composition::CompositionAnimation const& animation, Windows::Foundation::Numerics::float3 const& centerPoint) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScaleWithAnimation(get_abi(animation), get_abi(centerPoint), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker<D>::TryUpdateScaleWithAdditionalVelocity(float velocityInPercentPerSecond, Windows::Foundation::Numerics::float3 const& centerPoint) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker)->TryUpdateScaleWithAdditionalVelocity(velocityInPercentPerSecond, get_abi(centerPoint), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker2<D>::ConfigureCenterPointXInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker2)->ConfigureCenterPointXInertiaModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker2<D>::ConfigureCenterPointYInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker2)->ConfigureCenterPointYInertiaModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTracker3<D>::ConfigureVector2PositionInertiaModifiers(param::iterable<Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> const& modifiers) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker3)->ConfigureVector2PositionInertiaModifiers(get_abi(modifiers)));
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::TryUpdatePosition(Windows::Foundation::Numerics::float3 const& value, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const& option) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker4)->TryUpdatePositionWithOption(get_abi(value), get_abi(option), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::TryUpdatePositionBy(Windows::Foundation::Numerics::float3 const& amount, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const& option) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker4)->TryUpdatePositionByWithOption(get_abi(amount), get_abi(option), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTracker4<D>::IsInertiaFromImpulse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTracker4)->get_IsInertiaFromImpulse(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs)->get_RequestId(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs2<D>::IsFromBinding() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2)->get_IsFromBinding(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs)->get_RequestId(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs2<D>::IsFromBinding() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2)->get_IsFromBinding(&value));
    return value;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Condition() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->get_Condition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Condition(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->put_Condition(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Motion() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->get_Motion(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion<D>::Motion(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion)->put_Motion(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotionStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::Condition() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->get_Condition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::Condition(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->put_Condition(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ScalarNaturalMotionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::NaturalMotion() const
{
    Windows::UI::Composition::ScalarNaturalMotionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->get_NaturalMotion(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion<D>::NaturalMotion(Windows::UI::Composition::ScalarNaturalMotionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion)->put_NaturalMotion(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotionStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::Condition() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->get_Condition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::Condition(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->put_Condition(get_abi(value)));
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::RestingValue() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->get_RestingValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue<D>::RestingValue(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue)->put_RestingValue(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValueStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ModifiedRestingPosition() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ModifiedRestingPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ModifiedRestingScale() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ModifiedRestingScale(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::NaturalRestingPosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_NaturalRestingPosition(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::NaturalRestingScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_NaturalRestingScale(&value));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::PositionVelocityInPixelsPerSecond() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_PositionVelocityInPixelsPerSecond(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_RequestId(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs<D>::ScaleVelocityInPercentPerSecond() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs)->get_ScaleVelocityInPercentPerSecond(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs2<D>::IsInertiaFromImpulse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2)->get_IsInertiaFromImpulse(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs3<D>::IsFromBinding() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3)->get_IsFromBinding(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs)->get_RequestId(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs2<D>::IsFromBinding() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2)->get_IsFromBinding(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::CustomAnimationStateEntered(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->CustomAnimationStateEntered(get_abi(sender), get_abi(args)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::IdleStateEntered(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->IdleStateEntered(get_abi(sender), get_abi(args)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::InertiaStateEntered(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->InertiaStateEntered(get_abi(sender), get_abi(args)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::InteractingStateEntered(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->InteractingStateEntered(get_abi(sender), get_abi(args)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::RequestIgnored(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->RequestIgnored(get_abi(sender), get_abi(args)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerOwner<D>::ValuesChanged(Windows::UI::Composition::Interactions::InteractionTracker const& sender, Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerOwner)->ValuesChanged(get_abi(sender), get_abi(args)));
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerRequestIgnoredArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs)->get_RequestId(&value));
    return value;
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTracker consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::InteractionTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTracker consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics<D>::CreateWithOwner(Windows::UI::Composition::Compositor const& compositor, Windows::UI::Composition::Interactions::IInteractionTrackerOwner const& owner) const
{
    Windows::UI::Composition::Interactions::InteractionTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerStatics)->CreateWithOwner(get_abi(compositor), get_abi(owner), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2<D>::SetBindingMode(Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2, Windows::UI::Composition::Interactions::InteractionBindingAxisModes const& axisMode) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerStatics2)->SetBindingMode(get_abi(boundTracker1), get_abi(boundTracker2), get_abi(axisMode)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionBindingAxisModes consume_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2<D>::GetBindingMode(Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2) const
{
    Windows::UI::Composition::Interactions::InteractionBindingAxisModes result{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerStatics2)->GetBindingMode(get_abi(boundTracker1), get_abi(boundTracker2), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::RequestId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_RequestId(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs<D>::Scale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs)->get_Scale(&value));
    return value;
}

template <typename D> Windows::UI::Composition::ExpressionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::Condition() const
{
    Windows::UI::Composition::ExpressionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->get_Condition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::Condition(Windows::UI::Composition::ExpressionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->put_Condition(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Vector2NaturalMotionAnimation consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::NaturalMotion() const
{
    Windows::UI::Composition::Vector2NaturalMotionAnimation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->get_NaturalMotion(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion<D>::NaturalMotion(Windows::UI::Composition::Vector2NaturalMotionAnimation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion)->put_NaturalMotion(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion consume_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotionStatics<D>::Create(Windows::UI::Composition::Compositor const& compositor) const
{
    Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics)->Create(get_abi(compositor), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionXRailsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_IsPositionXRailsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionXRailsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_IsPositionXRailsEnabled(value));
}

template <typename D> bool consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionYRailsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_IsPositionYRailsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::IsPositionYRailsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_IsPositionYRailsEnabled(value));
}

template <typename D> Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ManipulationRedirectionMode() const
{
    Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ManipulationRedirectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ManipulationRedirectionMode(Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ManipulationRedirectionMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionChainingMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXChainingMode() const
{
    Windows::UI::Composition::Interactions::InteractionChainingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionXChainingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionXChainingMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionXSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionXSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionChainingMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYChainingMode() const
{
    Windows::UI::Composition::Interactions::InteractionChainingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionYChainingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionYChainingMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_PositionYSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_PositionYSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionChainingMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleChainingMode() const
{
    Windows::UI::Composition::Interactions::InteractionChainingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ScaleChainingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ScaleChainingMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceMode consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleSourceMode() const
{
    Windows::UI::Composition::Interactions::InteractionSourceMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_ScaleSourceMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->put_ScaleSourceMode(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::Source() const
{
    Windows::UI::Composition::Visual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource<D>::TryRedirectForManipulation(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource)->TryRedirectForManipulation(get_abi(pointerPoint)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::DeltaPosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_DeltaPosition(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::DeltaScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_DeltaScale(&value));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::PositionVelocity() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_PositionVelocity(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::Scale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_Scale(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ScaleVelocity() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->get_ScaleVelocity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureCenterPointXModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureCenterPointXModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureCenterPointYModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureCenterPointYModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaPositionXModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaPositionXModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaPositionYModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaPositionYModifiers(get_abi(conditionalValues)));
}

template <typename D> void consume_Windows_UI_Composition_Interactions_IVisualInteractionSource2<D>::ConfigureDeltaScaleModifiers(param::iterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const& conditionalValues) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource2)->ConfigureDeltaScaleModifiers(get_abi(conditionalValues)));
}

template <typename D> Windows::UI::Composition::Interactions::InteractionSourceConfiguration consume_Windows_UI_Composition_Interactions_IVisualInteractionSource3<D>::PointerWheelConfig() const
{
    Windows::UI::Composition::Interactions::InteractionSourceConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSource3)->get_PointerWheelConfig(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Interactions::VisualInteractionSource consume_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics<D>::Create(Windows::UI::Composition::Visual const& source) const
{
    Windows::UI::Composition::Interactions::VisualInteractionSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics)->Create(get_abi(source), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Interactions::VisualInteractionSource consume_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics2<D>::CreateFromIVisualElement(Windows::UI::Composition::IVisualElement const& source) const
{
    Windows::UI::Composition::Interactions::VisualInteractionSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2)->CreateFromIVisualElement(get_abi(source), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::ICompositionConditionalValue> : produce_base<D, Windows::UI::Composition::Interactions::ICompositionConditionalValue>
{
    int32_t WINRT_CALL get_Condition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Condition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Condition(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Value(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics> : produce_base<D, Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::CompositionConditionalValue), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::CompositionConditionalValue>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::ICompositionInteractionSource> : produce_base<D, Windows::UI::Composition::Interactions::ICompositionInteractionSource>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection> : produce_base<D, Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection>
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
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::UI::Composition::Interactions::ICompositionInteractionSource const&);
            this->shim().Add(*reinterpret_cast<Windows::UI::Composition::Interactions::ICompositionInteractionSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::UI::Composition::Interactions::ICompositionInteractionSource const&);
            this->shim().Remove(*reinterpret_cast<Windows::UI::Composition::Interactions::ICompositionInteractionSource const*>(&value));
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
struct produce<D, Windows::UI::Composition::Interactions::IInteractionSourceConfiguration> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionSourceConfiguration>
{
    int32_t WINRT_CALL get_PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().PositionXSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const&);
            this->shim().PositionXSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().PositionYSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const&);
            this->shim().PositionYSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode>(this->shim().ScaleSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const&);
            this->shim().ScaleSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTracker> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTracker>
{
    int32_t WINRT_CALL get_InteractionSources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSources, WINRT_WRAP(Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection));
            *value = detach_from<Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection>(this->shim().InteractionSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPositionRoundingSuggested(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPositionRoundingSuggested, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPositionRoundingSuggested());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().MaxPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxPosition(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPosition, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().MaxPosition(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxScale, WINRT_WRAP(void), float);
            this->shim().MaxScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinPosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().MinPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinPosition(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinPosition, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().MinPosition(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MinScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinScale, WINRT_WRAP(void), float);
            this->shim().MinScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalRestingPosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalRestingPosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().NaturalRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalRestingScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalRestingScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().NaturalRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Owner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Owner, WINRT_WRAP(Windows::UI::Composition::Interactions::IInteractionTrackerOwner));
            *value = detach_from<Windows::UI::Composition::Interactions::IInteractionTrackerOwner>(this->shim().Owner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionInertiaDecayRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionInertiaDecayRate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().PositionInertiaDecayRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionInertiaDecayRate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionInertiaDecayRate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const&);
            this->shim().PositionInertiaDecayRate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionVelocityInPixelsPerSecond(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionVelocityInPixelsPerSecond, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().PositionVelocityInPixelsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleInertiaDecayRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleInertiaDecayRate, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().ScaleInertiaDecayRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleInertiaDecayRate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleInertiaDecayRate, WINRT_WRAP(void), Windows::Foundation::IReference<float> const&);
            this->shim().ScaleInertiaDecayRate(*reinterpret_cast<Windows::Foundation::IReference<float> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleVelocityInPercentPerSecond(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleVelocityInPercentPerSecond, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ScaleVelocityInPercentPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AdjustPositionXIfGreaterThanThreshold(float adjustment, float positionThreshold) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdjustPositionXIfGreaterThanThreshold, WINRT_WRAP(void), float, float);
            this->shim().AdjustPositionXIfGreaterThanThreshold(adjustment, positionThreshold);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AdjustPositionYIfGreaterThanThreshold(float adjustment, float positionThreshold) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdjustPositionYIfGreaterThanThreshold, WINRT_WRAP(void), float, float);
            this->shim().AdjustPositionYIfGreaterThanThreshold(adjustment, positionThreshold);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigurePositionXInertiaModifiers(void* modifiers) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigurePositionXInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const&);
            this->shim().ConfigurePositionXInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigurePositionYInertiaModifiers(void* modifiers) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigurePositionYInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const&);
            this->shim().ConfigurePositionYInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureScaleInertiaModifiers(void* modifiers) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureScaleInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const&);
            this->shim().ConfigureScaleInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdatePosition(Windows::Foundation::Numerics::float3 value, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePosition, WINRT_WRAP(int32_t), Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePosition(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdatePositionBy(Windows::Foundation::Numerics::float3 amount, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePositionBy, WINRT_WRAP(int32_t), Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionBy(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&amount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdatePositionWithAnimation(void* animation, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePositionWithAnimation, WINRT_WRAP(int32_t), Windows::UI::Composition::CompositionAnimation const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionWithAnimation(*reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&animation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdatePositionWithAdditionalVelocity(Windows::Foundation::Numerics::float3 velocityInPixelsPerSecond, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePositionWithAdditionalVelocity, WINRT_WRAP(int32_t), Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionWithAdditionalVelocity(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&velocityInPixelsPerSecond)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateScale(float value, Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateScale, WINRT_WRAP(int32_t), float, Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdateScale(value, *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateScaleWithAnimation(void* animation, Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateScaleWithAnimation, WINRT_WRAP(int32_t), Windows::UI::Composition::CompositionAnimation const&, Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdateScaleWithAnimation(*reinterpret_cast<Windows::UI::Composition::CompositionAnimation const*>(&animation), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateScaleWithAdditionalVelocity(float velocityInPercentPerSecond, Windows::Foundation::Numerics::float3 centerPoint, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateScaleWithAdditionalVelocity, WINRT_WRAP(int32_t), float, Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<int32_t>(this->shim().TryUpdateScaleWithAdditionalVelocity(velocityInPercentPerSecond, *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&centerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTracker2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTracker2>
{
    int32_t WINRT_CALL ConfigureCenterPointXInertiaModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureCenterPointXInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureCenterPointXInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureCenterPointYInertiaModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureCenterPointYInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureCenterPointYInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTracker3> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTracker3>
{
    int32_t WINRT_CALL ConfigureVector2PositionInertiaModifiers(void* modifiers) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureVector2PositionInertiaModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> const&);
            this->shim().ConfigureVector2PositionInertiaModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> const*>(&modifiers));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTracker4> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTracker4>
{
    int32_t WINRT_CALL TryUpdatePositionWithOption(Windows::Foundation::Numerics::float3 value, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption option, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePosition, WINRT_WRAP(int32_t), Windows::Foundation::Numerics::float3 const&, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePosition(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdatePositionByWithOption(Windows::Foundation::Numerics::float3 amount, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption option, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdatePositionBy, WINRT_WRAP(int32_t), Windows::Foundation::Numerics::float3 const&, Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const&);
            *result = detach_from<int32_t>(this->shim().TryUpdatePositionBy(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&amount), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerClampingOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInertiaFromImpulse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInertiaFromImpulse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInertiaFromImpulse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2>
{
    int32_t WINRT_CALL get_IsFromBinding(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromBinding, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2>
{
    int32_t WINRT_CALL get_IsFromBinding(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromBinding, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion>
{
    int32_t WINRT_CALL get_Condition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Condition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Condition(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Motion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Motion, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Motion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Motion(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Motion, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Motion(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion>
{
    int32_t WINRT_CALL get_Condition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Condition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Condition(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalMotion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalMotion, WINRT_WRAP(Windows::UI::Composition::ScalarNaturalMotionAnimation));
            *value = detach_from<Windows::UI::Composition::ScalarNaturalMotionAnimation>(this->shim().NaturalMotion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NaturalMotion(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalMotion, WINRT_WRAP(void), Windows::UI::Composition::ScalarNaturalMotionAnimation const&);
            this->shim().NaturalMotion(*reinterpret_cast<Windows::UI::Composition::ScalarNaturalMotionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue>
{
    int32_t WINRT_CALL get_Condition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Condition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Condition(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RestingValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestingValue, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().RestingValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RestingValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestingValue, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().RestingValue(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs>
{
    int32_t WINRT_CALL get_ModifiedRestingPosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModifiedRestingPosition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().ModifiedRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModifiedRestingScale(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModifiedRestingScale, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().ModifiedRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalRestingPosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalRestingPosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().NaturalRestingPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalRestingScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalRestingScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().NaturalRestingScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionVelocityInPixelsPerSecond(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionVelocityInPixelsPerSecond, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().PositionVelocityInPixelsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleVelocityInPercentPerSecond(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleVelocityInPercentPerSecond, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ScaleVelocityInPercentPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2>
{
    int32_t WINRT_CALL get_IsInertiaFromImpulse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInertiaFromImpulse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInertiaFromImpulse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3>
{
    int32_t WINRT_CALL get_IsFromBinding(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromBinding, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2>
{
    int32_t WINRT_CALL get_IsFromBinding(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromBinding, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerOwner> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerOwner>
{
    int32_t WINRT_CALL CustomAnimationStateEntered(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomAnimationStateEntered, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs const&);
            this->shim().CustomAnimationStateEntered(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IdleStateEntered(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IdleStateEntered, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs const&);
            this->shim().IdleStateEntered(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InertiaStateEntered(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaStateEntered, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs const&);
            this->shim().InertiaStateEntered(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InteractingStateEntered(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractingStateEntered, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs const&);
            this->shim().InteractingStateEntered(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestIgnored(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestIgnored, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs const&);
            this->shim().RequestIgnored(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ValuesChanged(void* sender, void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValuesChanged, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs const&);
            this->shim().ValuesChanged(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&sender), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs>
{
    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerStatics> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTracker), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTracker>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithOwner(void* compositor, void* owner, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithOwner, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTracker), Windows::UI::Composition::Compositor const&, Windows::UI::Composition::Interactions::IInteractionTrackerOwner const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTracker>(this->shim().CreateWithOwner(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor), *reinterpret_cast<Windows::UI::Composition::Interactions::IInteractionTrackerOwner const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerStatics2> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerStatics2>
{
    int32_t WINRT_CALL SetBindingMode(void* boundTracker1, void* boundTracker2, Windows::UI::Composition::Interactions::InteractionBindingAxisModes axisMode) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBindingMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionBindingAxisModes const&);
            this->shim().SetBindingMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker1), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker2), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionBindingAxisModes const*>(&axisMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBindingMode(void* boundTracker1, void* boundTracker2, Windows::UI::Composition::Interactions::InteractionBindingAxisModes* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBindingMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionBindingAxisModes), Windows::UI::Composition::Interactions::InteractionTracker const&, Windows::UI::Composition::Interactions::InteractionTracker const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionBindingAxisModes>(this->shim().GetBindingMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker1), *reinterpret_cast<Windows::UI::Composition::Interactions::InteractionTracker const*>(&boundTracker2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RequestId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion>
{
    int32_t WINRT_CALL get_Condition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(Windows::UI::Composition::ExpressionAnimation));
            *value = detach_from<Windows::UI::Composition::ExpressionAnimation>(this->shim().Condition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Condition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Condition, WINRT_WRAP(void), Windows::UI::Composition::ExpressionAnimation const&);
            this->shim().Condition(*reinterpret_cast<Windows::UI::Composition::ExpressionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalMotion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalMotion, WINRT_WRAP(Windows::UI::Composition::Vector2NaturalMotionAnimation));
            *value = detach_from<Windows::UI::Composition::Vector2NaturalMotionAnimation>(this->shim().NaturalMotion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NaturalMotion(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalMotion, WINRT_WRAP(void), Windows::UI::Composition::Vector2NaturalMotionAnimation const&);
            this->shim().NaturalMotion(*reinterpret_cast<Windows::UI::Composition::Vector2NaturalMotionAnimation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics> : produce_base<D, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics>
{
    int32_t WINRT_CALL Create(void* compositor, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion), Windows::UI::Composition::Compositor const&);
            *result = detach_from<Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Compositor const*>(&compositor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSource> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSource>
{
    int32_t WINRT_CALL get_IsPositionXRailsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPositionXRailsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPositionXRailsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPositionXRailsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPositionXRailsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPositionXRailsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPositionYRailsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPositionYRailsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPositionYRailsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPositionYRailsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPositionYRailsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsPositionYRailsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationRedirectionMode(Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationRedirectionMode, WINRT_WRAP(Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode));
            *value = detach_from<Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode>(this->shim().ManipulationRedirectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ManipulationRedirectionMode(Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationRedirectionMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode const&);
            this->shim().ManipulationRedirectionMode(*reinterpret_cast<Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionXChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXChainingMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionChainingMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().PositionXChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionXChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXChainingMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionChainingMode const&);
            this->shim().PositionXChainingMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().PositionXSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionXSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionXSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceMode const&);
            this->shim().PositionXSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionYChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYChainingMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionChainingMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().PositionYChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionYChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYChainingMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionChainingMode const&);
            this->shim().PositionYChainingMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().PositionYSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PositionYSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionYSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceMode const&);
            this->shim().PositionYSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleChainingMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionChainingMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionChainingMode>(this->shim().ScaleChainingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleChainingMode(Windows::UI::Composition::Interactions::InteractionChainingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleChainingMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionChainingMode const&);
            this->shim().ScaleChainingMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionChainingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleSourceMode, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceMode));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceMode>(this->shim().ScaleSourceMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleSourceMode(Windows::UI::Composition::Interactions::InteractionSourceMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleSourceMode, WINRT_WRAP(void), Windows::UI::Composition::Interactions::InteractionSourceMode const&);
            this->shim().ScaleSourceMode(*reinterpret_cast<Windows::UI::Composition::Interactions::InteractionSourceMode const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Composition::Visual));
            *value = detach_from<Windows::UI::Composition::Visual>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRedirectForManipulation(void* pointerPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRedirectForManipulation, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&);
            this->shim().TryRedirectForManipulation(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSource2> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSource2>
{
    int32_t WINRT_CALL get_DeltaPosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaPosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().DeltaPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeltaScale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaScale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DeltaScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PositionVelocity(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionVelocity, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().PositionVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleVelocity(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleVelocity, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ScaleVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureCenterPointXModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureCenterPointXModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureCenterPointXModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureCenterPointYModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureCenterPointYModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureCenterPointYModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureDeltaPositionXModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureDeltaPositionXModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureDeltaPositionXModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureDeltaPositionYModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureDeltaPositionYModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureDeltaPositionYModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConfigureDeltaScaleModifiers(void* conditionalValues) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigureDeltaScaleModifiers, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const&);
            this->shim().ConfigureDeltaScaleModifiers(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Composition::Interactions::CompositionConditionalValue> const*>(&conditionalValues));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSource3> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSource3>
{
    int32_t WINRT_CALL get_PointerWheelConfig(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerWheelConfig, WINRT_WRAP(Windows::UI::Composition::Interactions::InteractionSourceConfiguration));
            *value = detach_from<Windows::UI::Composition::Interactions::InteractionSourceConfiguration>(this->shim().PointerWheelConfig());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics>
{
    int32_t WINRT_CALL Create(void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Composition::Interactions::VisualInteractionSource), Windows::UI::Composition::Visual const&);
            *result = detach_from<Windows::UI::Composition::Interactions::VisualInteractionSource>(this->shim().Create(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2> : produce_base<D, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2>
{
    int32_t WINRT_CALL CreateFromIVisualElement(void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIVisualElement, WINRT_WRAP(Windows::UI::Composition::Interactions::VisualInteractionSource), Windows::UI::Composition::IVisualElement const&);
            *result = detach_from<Windows::UI::Composition::Interactions::VisualInteractionSource>(this->shim().CreateFromIVisualElement(*reinterpret_cast<Windows::UI::Composition::IVisualElement const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Interactions {

inline Windows::UI::Composition::Interactions::CompositionConditionalValue CompositionConditionalValue::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<CompositionConditionalValue, Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::InteractionTracker InteractionTracker::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<InteractionTracker, Windows::UI::Composition::Interactions::IInteractionTrackerStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::InteractionTracker InteractionTracker::CreateWithOwner(Windows::UI::Composition::Compositor const& compositor, Windows::UI::Composition::Interactions::IInteractionTrackerOwner const& owner)
{
    return impl::call_factory<InteractionTracker, Windows::UI::Composition::Interactions::IInteractionTrackerStatics>([&](auto&& f) { return f.CreateWithOwner(compositor, owner); });
}

inline void InteractionTracker::SetBindingMode(Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2, Windows::UI::Composition::Interactions::InteractionBindingAxisModes const& axisMode)
{
    impl::call_factory<InteractionTracker, Windows::UI::Composition::Interactions::IInteractionTrackerStatics2>([&](auto&& f) { return f.SetBindingMode(boundTracker1, boundTracker2, axisMode); });
}

inline Windows::UI::Composition::Interactions::InteractionBindingAxisModes InteractionTracker::GetBindingMode(Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker1, Windows::UI::Composition::Interactions::InteractionTracker const& boundTracker2)
{
    return impl::call_factory<InteractionTracker, Windows::UI::Composition::Interactions::IInteractionTrackerStatics2>([&](auto&& f) { return f.GetBindingMode(boundTracker1, boundTracker2); });
}

inline Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion InteractionTrackerInertiaMotion::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<InteractionTrackerInertiaMotion, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion InteractionTrackerInertiaNaturalMotion::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<InteractionTrackerInertiaNaturalMotion, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue InteractionTrackerInertiaRestingValue::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<InteractionTrackerInertiaRestingValue, Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion InteractionTrackerVector2InertiaNaturalMotion::Create(Windows::UI::Composition::Compositor const& compositor)
{
    return impl::call_factory<InteractionTrackerVector2InertiaNaturalMotion, Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics>([&](auto&& f) { return f.Create(compositor); });
}

inline Windows::UI::Composition::Interactions::VisualInteractionSource VisualInteractionSource::Create(Windows::UI::Composition::Visual const& source)
{
    return impl::call_factory<VisualInteractionSource, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics>([&](auto&& f) { return f.Create(source); });
}

inline Windows::UI::Composition::Interactions::VisualInteractionSource VisualInteractionSource::CreateFromIVisualElement(Windows::UI::Composition::IVisualElement const& source)
{
    return impl::call_factory<VisualInteractionSource, Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2>([&](auto&& f) { return f.CreateFromIVisualElement(source); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValue> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSource> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTracker> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTracker2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTracker3> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTracker4> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTracker4> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerOwner> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSource3> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::CompositionConditionalValue> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::CompositionInteractionSourceCollection> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionSourceConfiguration> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTracker> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTracker> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerCustomAnimationStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerIdleStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaNaturalMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaRestingValue> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInertiaStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerInteractingStateEnteredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerRequestIgnoredArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerValuesChangedArgs> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaNaturalMotion> {};
template<> struct hash<winrt::Windows::UI::Composition::Interactions::VisualInteractionSource> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Interactions::VisualInteractionSource> {};

}
