// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/Windows.UI.Xaml.Media.h"

namespace winrt::impl {

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IBackEase<D>::Amplitude() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBackEase)->get_Amplitude(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IBackEase<D>::Amplitude(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBackEase)->put_Amplitude(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IBackEaseStatics<D>::AmplitudeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBackEaseStatics)->get_AmplitudeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration consume_Windows_UI_Xaml_Media_Animation_IBasicConnectedAnimationConfigurationFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::Storyboard consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboard<D>::Storyboard() const
{
    Windows::UI::Xaml::Media::Animation::Storyboard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBeginStoryboard)->get_Storyboard(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboard<D>::Storyboard(Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBeginStoryboard)->put_Storyboard(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IBeginStoryboardStatics<D>::StoryboardProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics)->get_StoryboardProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounces() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEase)->get_Bounces(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounces(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEase)->put_Bounces(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounciness() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEase)->get_Bounciness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IBounceEase<D>::Bounciness(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEase)->put_Bounciness(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IBounceEaseStatics<D>::BouncesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEaseStatics)->get_BouncesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IBounceEaseStatics<D>::BouncinessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IBounceEaseStatics)->get_BouncinessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::From() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::From(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_From(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::To() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::To(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_To(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::By() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_By(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::By(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_By(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_EasingFunction(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimation<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimation)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::FromProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_FromProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::ToProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_ToProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::ByProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_ByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::KeyFrames() const
{
    Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->get_KeyFrames(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::Value() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::Value(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->put_Value(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeyTime consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::KeyTime() const
{
    Windows::UI::Xaml::Media::Animation::KeyTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->get_KeyTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrame<D>::KeyTime(Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrame)->put_KeyTime(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::ColorKeyFrame consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::ColorKeyFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IColorKeyFrameStatics<D>::KeyTimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics)->get_KeyTimeProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfo<D>::IsStaggeringEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo)->get_IsStaggeringEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfo<D>::IsStaggeringEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo)->put_IsStaggeringEnabled(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::IsStaggeringEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->get_IsStaggeringEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::IsStaggerElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->get_IsStaggerElementProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::GetIsStaggerElement(Windows::UI::Xaml::UIElement const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->GetIsStaggerElement(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ICommonNavigationTransitionInfoStatics<D>::SetIsStaggerElement(Windows::UI::Xaml::UIElement const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics)->SetIsStaggerElement(get_abi(element), value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Animation::ConnectedAnimation, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed_revoker consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Animation::ConnectedAnimation, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->remove_Completed(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::TryStart(Windows::UI::Xaml::UIElement const& destination) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->TryStart(get_abi(destination), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation<D>::Cancel() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation)->Cancel());
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::IsScaleAnimationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->get_IsScaleAnimationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::IsScaleAnimationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->put_IsScaleAnimationEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::TryStart(Windows::UI::Xaml::UIElement const& destination, param::iterable<Windows::UI::Xaml::UIElement> const& coordinatedElements) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->TryStartWithCoordinatedElements(get_abi(destination), get_abi(coordinatedElements), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation2<D>::SetAnimationComponent(Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent const& component, Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation2)->SetAnimationComponent(get_abi(component), get_abi(animation)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation3<D>::Configuration() const
{
    Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation3)->get_Configuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimation3<D>::Configuration(Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimation3)->put_Configuration(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->get_DefaultDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->put_DefaultDuration(get_abi(value)));
}

template <typename D> Windows::UI::Composition::CompositionEasingFunction consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultEasingFunction() const
{
    Windows::UI::Composition::CompositionEasingFunction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->get_DefaultEasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::DefaultEasingFunction(Windows::UI::Composition::CompositionEasingFunction const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->put_DefaultEasingFunction(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::ConnectedAnimation consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::PrepareToAnimate(param::hstring const& key, Windows::UI::Xaml::UIElement const& source) const
{
    Windows::UI::Xaml::Media::Animation::ConnectedAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->PrepareToAnimate(get_abi(key), get_abi(source), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Animation::ConnectedAnimation consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationService<D>::GetAnimation(param::hstring const& key) const
{
    Windows::UI::Xaml::Media::Animation::ConnectedAnimation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationService)->GetAnimation(get_abi(key), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Animation::ConnectedAnimationService consume_Windows_UI_Xaml_Media_Animation_IConnectedAnimationServiceStatics<D>::GetForCurrentView() const
{
    Windows::UI::Xaml::Media::Animation::ConnectedAnimationService result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::HorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->put_HorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->get_VerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransition<D>::VerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransition)->put_VerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransitionStatics<D>::HorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics)->get_HorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContentThemeTransitionStatics<D>::VerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics)->get_VerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfo<D>::ExitElement() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo)->get_ExitElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfo<D>::ExitElement(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo)->put_ExitElement(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::ExitElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_ExitElementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::IsEntranceElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_IsEntranceElementProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetIsEntranceElement(Windows::UI::Xaml::UIElement const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetIsEntranceElement(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetIsEntranceElement(Windows::UI::Xaml::UIElement const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetIsEntranceElement(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::IsExitElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_IsExitElementProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetIsExitElement(Windows::UI::Xaml::UIElement const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetIsExitElement(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetIsExitElement(Windows::UI::Xaml::UIElement const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetIsExitElement(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::ExitElementContainerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->get_ExitElementContainerProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::GetExitElementContainer(Windows::UI::Xaml::Controls::ListViewBase const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->GetExitElementContainer(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IContinuumNavigationTransitionInfoStatics<D>::SetExitElementContainer(Windows::UI::Xaml::Controls::ListViewBase const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics)->SetExitElementContainer(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration consume_Windows_UI_Xaml_Media_Animation_IDirectConnectedAnimationConfigurationFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::From() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::From(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_From(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::To() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::To(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_To(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::By() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_By(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::By(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_By(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_EasingFunction(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimation<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimation)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::FromProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_FromProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::ToProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_ToProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::ByProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_ByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::KeyFrames() const
{
    Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->get_KeyFrames(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::Value() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::Value(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->put_Value(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeyTime consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::KeyTime() const
{
    Windows::UI::Xaml::Media::Animation::KeyTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->get_KeyTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrame<D>::KeyTime(Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame)->put_KeyTime(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::DoubleKeyFrame consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::DoubleKeyFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDoubleKeyFrameStatics<D>::KeyTimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics)->get_KeyTimeProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDragItemThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::ToOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_ToOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::ToOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_ToOffset(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::AnimationDirection consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::Direction() const
{
    Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimation<D>::Direction(Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation)->put_Direction(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::ToOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_ToOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDragOverThemeAnimationStatics<D>::DirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics)->get_DirectionProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_EntranceTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_EntranceTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_EntranceTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::EntranceTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_EntranceTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_ExitTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_ExitTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->get_ExitTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimation<D>::ExitTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation)->put_ExitTarget(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::EntranceTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_EntranceTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::EntranceTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_EntranceTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::ExitTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_ExitTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillInThemeAnimationStatics<D>::ExitTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics)->get_ExitTargetProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_EntranceTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_EntranceTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_EntranceTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::EntranceTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_EntranceTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_ExitTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_ExitTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->get_ExitTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimation<D>::ExitTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation)->put_ExitTarget(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::EntranceTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_EntranceTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::EntranceTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_EntranceTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::ExitTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_ExitTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDrillOutThemeAnimationStatics<D>::ExitTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics)->get_ExitTargetProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IDropTargetItemThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrame<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrame<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame)->put_EasingFunction(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEasingColorKeyFrameStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrame<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrame<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame)->put_EasingFunction(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEasingDoubleKeyFrameStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingMode consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::EasingMode() const
{
    Windows::UI::Xaml::Media::Animation::EasingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->get_EasingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::EasingMode(Windows::UI::Xaml::Media::Animation::EasingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->put_EasingMode(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBase<D>::Ease(double normalizedTime) const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingFunctionBase)->Ease(normalizedTime, &result));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEasingFunctionBaseStatics<D>::EasingModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics)->get_EasingModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrame<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrame<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame)->put_EasingFunction(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEasingPointKeyFrameStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransition<D>::Edge() const
{
    Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition)->get_Edge(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransition<D>::Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition)->put_Edge(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEdgeUIThemeTransitionStatics<D>::EdgeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics)->get_EdgeProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Oscillations() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEase)->get_Oscillations(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Oscillations(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEase)->put_Oscillations(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Springiness() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEase)->get_Springiness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IElasticEase<D>::Springiness(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEase)->put_Springiness(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IElasticEaseStatics<D>::OscillationsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEaseStatics)->get_OscillationsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IElasticEaseStatics<D>::SpringinessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IElasticEaseStatics)->get_SpringinessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::IsTargetElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->get_IsTargetElementProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::GetIsTargetElement(Windows::UI::Xaml::UIElement const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->GetIsTargetElement(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEntranceNavigationTransitionInfoStatics<D>::SetIsTargetElement(Windows::UI::Xaml::UIElement const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics)->SetIsTargetElement(get_abi(element), value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_FromHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_FromVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::FromVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_FromVerticalOffset(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::IsStaggeringEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->get_IsStaggeringEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransition<D>::IsStaggeringEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition)->put_IsStaggeringEnabled(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::FromHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_FromHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::FromVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_FromVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IEntranceThemeTransitionStatics<D>::IsStaggeringEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics)->get_IsStaggeringEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IExponentialEase<D>::Exponent() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IExponentialEase)->get_Exponent(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IExponentialEase<D>::Exponent(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IExponentialEase)->put_Exponent(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IExponentialEaseStatics<D>::ExponentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics)->get_ExponentProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IFadeInThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IFadeOutThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfiguration2<D>::IsShadowEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2)->get_IsShadowEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfiguration2<D>::IsShadowEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2)->put_IsShadowEnabled(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration consume_Windows_UI_Xaml_Media_Animation_IGravityConnectedAnimationConfigurationFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint1() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IKeySpline)->get_ControlPoint1(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint1(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IKeySpline)->put_ControlPoint1(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint2() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IKeySpline)->get_ControlPoint2(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IKeySpline<D>::ControlPoint2(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IKeySpline)->put_ControlPoint2(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeyTime consume_Windows_UI_Xaml_Media_Animation_IKeyTimeHelperStatics<D>::FromTimeSpan(Windows::Foundation::TimeSpan const& timeSpan) const
{
    Windows::UI::Xaml::Media::Animation::KeyTime result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics)->FromTimeSpan(get_abi(timeSpan), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransition<D>::DefaultNavigationTransitionInfo() const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationThemeTransition)->get_DefaultNavigationTransitionInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransition<D>::DefaultNavigationTransitionInfo(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationThemeTransition)->put_DefaultNavigationTransitionInfo(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_INavigationThemeTransitionStatics<D>::DefaultNavigationTransitionInfoProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics)->get_DefaultNavigationTransitionInfoProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoOverrides<D>::GetNavigationStateCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides)->GetNavigationStateCore(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_INavigationTransitionInfoOverrides<D>::SetNavigationStateCore(param::hstring const& navigationState) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides)->SetNavigationStateCore(get_abi(navigationState)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::KeyFrames() const
{
    Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->get_KeyFrames(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IObjectAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::Value(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->put_Value(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeyTime consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::KeyTime() const
{
    Windows::UI::Xaml::Media::Animation::KeyTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->get_KeyTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrame<D>::KeyTime(Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrame)->put_KeyTime(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::ObjectKeyFrame consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::ObjectKeyFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IObjectKeyFrameStatics<D>::KeyTimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics)->get_KeyTimeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransition<D>::Edge() const
{
    Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPaneThemeTransition)->get_Edge(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransition<D>::Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPaneThemeTransition)->put_Edge(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPaneThemeTransitionStatics<D>::EdgeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics)->get_EdgeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::From() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::From(optional<Windows::Foundation::Point> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_From(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::To() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::To(optional<Windows::Foundation::Point> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_To(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::By() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_By(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::By(optional<Windows::Foundation::Point> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_By(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_EasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_EasingFunction(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimation<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimation)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::FromProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_FromProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::ToProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_ToProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::ByProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_ByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::EasingFunctionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_EasingFunctionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::KeyFrames() const
{
    Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->get_KeyFrames(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::EnableDependentAnimation() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->get_EnableDependentAnimation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFrames<D>::EnableDependentAnimation(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames)->put_EnableDependentAnimation(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointAnimationUsingKeyFramesStatics<D>::EnableDependentAnimationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics)->get_EnableDependentAnimationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::Value() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::Value(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->put_Value(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeyTime consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::KeyTime() const
{
    Windows::UI::Xaml::Media::Animation::KeyTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->get_KeyTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrame<D>::KeyTime(Windows::UI::Xaml::Media::Animation::KeyTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrame)->put_KeyTime(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::PointKeyFrame consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::PointKeyFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointKeyFrameStatics<D>::KeyTimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics)->get_KeyTimeProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointerDownThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPointerUpThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_FromHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->get_FromVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimation<D>::FromVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation)->put_FromVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_FromHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopInThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics)->get_FromVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopOutThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->put_FromHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->get_FromVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransition<D>::FromVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransition)->put_FromVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransitionStatics<D>::FromHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics)->get_FromHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPopupThemeTransitionStatics<D>::FromVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics)->get_FromVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IPowerEase<D>::Power() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPowerEase)->get_Power(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IPowerEase<D>::Power(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPowerEase)->put_Power(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IPowerEaseStatics<D>::PowerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IPowerEaseStatics)->get_PowerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::RepeatBehavior consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::Forever() const
{
    Windows::UI::Xaml::Media::Animation::RepeatBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->get_Forever(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::RepeatBehavior consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::FromCount(double count) const
{
    Windows::UI::Xaml::Media::Animation::RepeatBehavior result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->FromCount(count, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Animation::RepeatBehavior consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::FromDuration(Windows::Foundation::TimeSpan const& duration) const
{
    Windows::UI::Xaml::Media::Animation::RepeatBehavior result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->FromDuration(get_abi(duration), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::GetHasCount(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->GetHasCount(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::GetHasDuration(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->GetHasDuration(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IRepeatBehaviorHelperStatics<D>::Equals(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target, Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_FromHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->get_FromVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimation<D>::FromVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation)->put_FromVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_FromHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics)->get_FromVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransition2<D>::IsStaggeringEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2)->get_IsStaggeringEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransition2<D>::IsStaggeringEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2)->put_IsStaggeringEnabled(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IRepositionThemeTransitionStatics2<D>::IsStaggeringEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2)->get_IsStaggeringEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfo2<D>::Effect() const
{
    Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2)->get_Effect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfo2<D>::Effect(Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2)->put_Effect(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISlideNavigationTransitionInfoStatics2<D>::EffectProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2)->get_EffectProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeySpline consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrame<D>::KeySpline() const
{
    Windows::UI::Xaml::Media::Animation::KeySpline value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame)->get_KeySpline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrame<D>::KeySpline(Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame)->put_KeySpline(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplineColorKeyFrameStatics<D>::KeySplineProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics)->get_KeySplineProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeySpline consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrame<D>::KeySpline() const
{
    Windows::UI::Xaml::Media::Animation::KeySpline value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame)->get_KeySpline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrame<D>::KeySpline(Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame)->put_KeySpline(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplineDoubleKeyFrameStatics<D>::KeySplineProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics)->get_KeySplineProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::KeySpline consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrame<D>::KeySpline() const
{
    Windows::UI::Xaml::Media::Animation::KeySpline value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame)->get_KeySpline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrame<D>::KeySpline(Windows::UI::Xaml::Media::Animation::KeySpline const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame)->put_KeySpline(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplinePointKeyFrameStatics<D>::KeySplineProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics)->get_KeySplineProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTarget(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OpenedLength(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OpenedLength(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OpenedLength(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ClosedLength(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ClosedLength(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ClosedLength(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OffsetFromCenter() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_OffsetFromCenter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::OffsetFromCenter(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_OffsetFromCenter(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::AnimationDirection consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationDirection() const
{
    Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTranslationDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTranslationDirection(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->get_ContentTranslationOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimation<D>::ContentTranslationOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation)->put_ContentTranslationOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OpenedLengthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OpenedLengthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ClosedLengthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ClosedLengthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::OffsetFromCenterProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_OffsetFromCenterProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTranslationDirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTranslationDirectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitCloseThemeAnimationStatics<D>::ContentTranslationOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics)->get_ContentTranslationOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedTarget(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTargetName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTarget(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OpenedLength(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OpenedLength(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OpenedLength(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ClosedLength(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ClosedLength(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ClosedLength(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OffsetFromCenter() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_OffsetFromCenter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::OffsetFromCenter(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_OffsetFromCenter(value));
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::AnimationDirection consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationDirection() const
{
    Windows::UI::Xaml::Controls::Primitives::AnimationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTranslationDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTranslationDirection(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->get_ContentTranslationOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimation<D>::ContentTranslationOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation)->put_ContentTranslationOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OpenedLengthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OpenedLengthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ClosedLengthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ClosedLengthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::OffsetFromCenterProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_OffsetFromCenterProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTranslationDirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTranslationDirectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISplitOpenThemeAnimationStatics<D>::ContentTranslationOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics)->get_ContentTranslationOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::TimelineCollection consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Children() const
{
    Windows::UI::Xaml::Media::Animation::TimelineCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->get_Children(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Seek(Windows::Foundation::TimeSpan const& offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->Seek(get_abi(offset)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->Stop());
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Begin() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->Begin());
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->Pause());
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->Resume());
}

template <typename D> Windows::UI::Xaml::Media::Animation::ClockState consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::GetCurrentState() const
{
    Windows::UI::Xaml::Media::Animation::ClockState result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->GetCurrentState(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::GetCurrentTime() const
{
    Windows::Foundation::TimeSpan result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->GetCurrentTime(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::SeekAlignedToLastTick(Windows::Foundation::TimeSpan const& offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->SeekAlignedToLastTick(get_abi(offset)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboard<D>::SkipToFill() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboard)->SkipToFill());
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::TargetPropertyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->get_TargetPropertyProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::GetTargetProperty(Windows::UI::Xaml::Media::Animation::Timeline const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->GetTargetProperty(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTargetProperty(Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& path) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTargetProperty(get_abi(element), get_abi(path)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::GetTargetName(Windows::UI::Xaml::Media::Animation::Timeline const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->GetTargetName(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTargetName(Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& name) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTargetName(get_abi(element), get_abi(name)));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_IStoryboardStatics<D>::SetTarget(Windows::UI::Xaml::Media::Animation::Timeline const& timeline, Windows::UI::Xaml::DependencyObject const& target) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::IStoryboardStatics)->SetTarget(get_abi(timeline), get_abi(target)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_FromHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_FromHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->get_FromVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimation<D>::FromVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation)->put_FromVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::FromHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_FromHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeBackThemeAnimationStatics<D>::FromVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics)->get_FromVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_TargetName(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_ToHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_ToHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->get_ToVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimation<D>::ToVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation)->put_ToVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::TargetNameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_TargetNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::ToHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_ToHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ISwipeHintThemeAnimationStatics<D>::ToVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics)->get_ToVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::AutoReverse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_AutoReverse(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::AutoReverse(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_AutoReverse(value));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::BeginTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_BeginTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::BeginTime(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_BeginTime(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Duration() const
{
    Windows::UI::Xaml::Duration value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Duration(Windows::UI::Xaml::Duration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_Duration(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::SpeedRatio() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_SpeedRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::SpeedRatio(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_SpeedRatio(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::FillBehavior consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::FillBehavior() const
{
    Windows::UI::Xaml::Media::Animation::FillBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_FillBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::FillBehavior(Windows::UI::Xaml::Media::Animation::FillBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_FillBehavior(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::RepeatBehavior consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::RepeatBehavior() const
{
    Windows::UI::Xaml::Media::Animation::RepeatBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->get_RepeatBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::RepeatBehavior(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->put_RepeatBehavior(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed_revoker consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimeline<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimeline)->remove_Completed(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::Timeline consume_Windows_UI_Xaml_Media_Animation_ITimelineFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Animation::Timeline value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AllowDependentAnimations() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_AllowDependentAnimations(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AllowDependentAnimations(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->put_AllowDependentAnimations(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::AutoReverseProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_AutoReverseProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::BeginTimeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_BeginTimeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::DurationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_DurationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::SpeedRatioProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_SpeedRatioProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::FillBehaviorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_FillBehaviorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Animation_ITimelineStatics<D>::RepeatBehaviorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Animation::ITimelineStatics)->get_RepeatBehaviorProperty(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBackEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBackEase>
{
    int32_t WINRT_CALL get_Amplitude(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amplitude, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Amplitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Amplitude(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Amplitude, WINRT_WRAP(void), double);
            this->shim().Amplitude(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBackEaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBackEaseStatics>
{
    int32_t WINRT_CALL get_AmplitudeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AmplitudeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AmplitudeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBeginStoryboard> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBeginStoryboard>
{
    int32_t WINRT_CALL get_Storyboard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::Storyboard));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Storyboard(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Storyboard const&);
            this->shim().Storyboard(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics>
{
    int32_t WINRT_CALL get_StoryboardProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoryboardProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StoryboardProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBounceEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBounceEase>
{
    int32_t WINRT_CALL get_Bounces(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounces, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Bounces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounces(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounces, WINRT_WRAP(void), int32_t);
            this->shim().Bounces(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounciness(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounciness, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Bounciness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounciness(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounciness, WINRT_WRAP(void), double);
            this->shim().Bounciness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IBounceEaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IBounceEaseStatics>
{
    int32_t WINRT_CALL get_BouncesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BouncesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BouncesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BouncinessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BouncinessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BouncinessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ICircleEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::ICircleEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorAnimation>
{
    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().From(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().To(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_By(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_By(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().By(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>
{
    int32_t WINRT_CALL get_FromProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames>
{
    int32_t WINRT_CALL get_KeyFrames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrames, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics>
{
    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrame>
{
    int32_t WINRT_CALL get_Value(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Value(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeyTime));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeyTime const&);
            this->shim().KeyTime(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ColorKeyFrame), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::ColorKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics>
{
    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo>
{
    int32_t WINRT_CALL get_IsStaggeringEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStaggeringEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(void), bool);
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>
{
    int32_t WINRT_CALL get_IsStaggeringEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStaggerElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggerElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggerElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsStaggerElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsStaggerElement, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<bool>(this->shim().GetIsStaggerElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsStaggerElement(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsStaggerElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, bool);
            this->shim().SetIsStaggerElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation>
{
    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Animation::ConnectedAnimation, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Animation::ConnectedAnimation, Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL TryStart(void* destination, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStart, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<bool>(this->shim().TryStart(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Cancel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void));
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation2> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation2>
{
    int32_t WINRT_CALL get_IsScaleAnimationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScaleAnimationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScaleAnimationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsScaleAnimationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScaleAnimationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsScaleAnimationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStartWithCoordinatedElements(void* destination, void* coordinatedElements, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStart, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&, Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> const&);
            *result = detach_from<bool>(this->shim().TryStart(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&destination), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement> const*>(&coordinatedElements)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAnimationComponent(Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent component, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAnimationComponent, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent const&, Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().SetAnimationComponent(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::ConnectedAnimationComponent const*>(&component), *reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation3> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimation3>
{
    int32_t WINRT_CALL get_Configuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Configuration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration const&);
            this->shim().Configuration(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationService> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationService>
{
    int32_t WINRT_CALL get_DefaultDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DefaultDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DefaultDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultEasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultEasingFunction, WINRT_WRAP(Windows::UI::Composition::CompositionEasingFunction));
            *value = detach_from<Windows::UI::Composition::CompositionEasingFunction>(this->shim().DefaultEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultEasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultEasingFunction, WINRT_WRAP(void), Windows::UI::Composition::CompositionEasingFunction const&);
            this->shim().DefaultEasingFunction(*reinterpret_cast<Windows::UI::Composition::CompositionEasingFunction const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareToAnimate(void* key, void* source, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareToAnimate, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ConnectedAnimation), hstring const&, Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Xaml::Media::Animation::ConnectedAnimation>(this->shim().PrepareToAnimate(*reinterpret_cast<hstring const*>(&key), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnimation(void* key, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnimation, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ConnectedAnimation), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Media::Animation::ConnectedAnimation>(this->shim().GetAnimation(*reinterpret_cast<hstring const*>(&key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ConnectedAnimationService));
            *result = detach_from<Windows::UI::Xaml::Media::Animation::ConnectedAnimationService>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IContentThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IContentThemeTransition>
{
    int32_t WINRT_CALL get_HorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(void), double);
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(void), double);
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics>
{
    int32_t WINRT_CALL get_HorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo>
{
    int32_t WINRT_CALL get_ExitElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitElement, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().ExitElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().ExitElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>
{
    int32_t WINRT_CALL get_ExitElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEntranceElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEntranceElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsEntranceElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsEntranceElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsEntranceElement, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<bool>(this->shim().GetIsEntranceElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsEntranceElement(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsEntranceElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, bool);
            this->shim().SetIsEntranceElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsExitElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExitElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsExitElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsExitElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsExitElement, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<bool>(this->shim().GetIsExitElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsExitElement(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsExitElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, bool);
            this->shim().SetIsExitElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitElementContainerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitElementContainerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitElementContainerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetExitElementContainer(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetExitElementContainer, WINRT_WRAP(bool), Windows::UI::Xaml::Controls::ListViewBase const&);
            *result = detach_from<bool>(this->shim().GetExitElementContainer(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewBase const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetExitElementContainer(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetExitElementContainer, WINRT_WRAP(void), Windows::UI::Xaml::Controls::ListViewBase const&, bool);
            this->shim().SetExitElementContainer(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewBase const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ICubicEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::ICubicEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimation>
{
    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().From(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().To(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_By(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_By(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().By(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>
{
    int32_t WINRT_CALL get_FromProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames>
{
    int32_t WINRT_CALL get_KeyFrames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrames, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics>
{
    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame>
{
    int32_t WINRT_CALL get_Value(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), double);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeyTime));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeyTime const&);
            this->shim().KeyTime(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::DoubleKeyFrame), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::DoubleKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics>
{
    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ToOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToOffset, WINRT_WRAP(void), double);
            this->shim().ToOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Controls::Primitives::AnimationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::AnimationDirection));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Direction(Windows::UI::Xaml::Controls::Primitives::AnimationDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::AnimationDirection const&);
            this->shim().Direction(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation>
{
    int32_t WINRT_CALL get_EntranceTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EntranceTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EntranceTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().EntranceTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EntranceTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().EntranceTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EntranceTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().EntranceTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExitTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ExitTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ExitTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ExitTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>
{
    int32_t WINRT_CALL get_EntranceTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EntranceTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation>
{
    int32_t WINRT_CALL get_EntranceTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EntranceTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EntranceTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().EntranceTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EntranceTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().EntranceTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EntranceTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().EntranceTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExitTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ExitTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ExitTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ExitTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>
{
    int32_t WINRT_CALL get_EntranceTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EntranceTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntranceTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EntranceTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame>
{
    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics>
{
    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame>
{
    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics>
{
    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBase>
{
    int32_t WINRT_CALL get_EasingMode(Windows::UI::Xaml::Media::Animation::EasingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingMode, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingMode));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingMode>(this->shim().EasingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingMode(Windows::UI::Xaml::Media::Animation::EasingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingMode, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingMode const&);
            this->shim().EasingMode(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Ease(double normalizedTime, double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ease, WINRT_WRAP(double), double);
            *result = detach_from<double>(this->shim().Ease(normalizedTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics>
{
    int32_t WINRT_CALL get_EasingModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame>
{
    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics>
{
    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition>
{
    int32_t WINRT_CALL get_Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Edge, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Edge, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const&);
            this->shim().Edge(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics>
{
    int32_t WINRT_CALL get_EdgeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EdgeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EdgeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IElasticEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IElasticEase>
{
    int32_t WINRT_CALL get_Oscillations(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Oscillations, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Oscillations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Oscillations(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Oscillations, WINRT_WRAP(void), int32_t);
            this->shim().Oscillations(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Springiness(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Springiness, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Springiness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Springiness(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Springiness, WINRT_WRAP(void), double);
            this->shim().Springiness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IElasticEaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IElasticEaseStatics>
{
    int32_t WINRT_CALL get_OscillationsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OscillationsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OscillationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpringinessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpringinessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SpringinessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics>
{
    int32_t WINRT_CALL get_IsTargetElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTargetElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTargetElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsTargetElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsTargetElement, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<bool>(this->shim().GetIsTargetElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsTargetElement(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsTargetElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, bool);
            this->shim().SetIsTargetElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition>
{
    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(void), double);
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStaggeringEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStaggeringEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(void), bool);
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics>
{
    int32_t WINRT_CALL get_FromHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStaggeringEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IExponentialEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IExponentialEase>
{
    int32_t WINRT_CALL get_Exponent(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exponent, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Exponent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Exponent(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exponent, WINRT_WRAP(void), double);
            this->shim().Exponent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics>
{
    int32_t WINRT_CALL get_ExponentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExponentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExponentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration> : produce_base<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2> : produce_base<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2>
{
    int32_t WINRT_CALL get_IsShadowEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShadowEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsShadowEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsShadowEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShadowEnabled, WINRT_WRAP(void), bool);
            this->shim().IsShadowEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IKeySpline> : produce_base<D, Windows::UI::Xaml::Media::Animation::IKeySpline>
{
    int32_t WINRT_CALL get_ControlPoint1(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint1, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().ControlPoint1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ControlPoint1(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint1, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().ControlPoint1(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlPoint2(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint2, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().ControlPoint2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ControlPoint2(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlPoint2, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().ControlPoint2(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IKeyTimeHelper> : produce_base<D, Windows::UI::Xaml::Media::Animation::IKeyTimeHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics>
{
    int32_t WINRT_CALL FromTimeSpan(Windows::Foundation::TimeSpan timeSpan, struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromTimeSpan, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeyTime), Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().FromTimeSpan(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeSpan)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::INavigationThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::INavigationThemeTransition>
{
    int32_t WINRT_CALL get_DefaultNavigationTransitionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultNavigationTransitionInfo, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().DefaultNavigationTransitionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultNavigationTransitionInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultNavigationTransitionInfo, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const&);
            this->shim().DefaultNavigationTransitionInfo(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics>
{
    int32_t WINRT_CALL get_DefaultNavigationTransitionInfoProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultNavigationTransitionInfoProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DefaultNavigationTransitionInfoProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides> : produce_base<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
{
    int32_t WINRT_CALL GetNavigationStateCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNavigationStateCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetNavigationStateCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNavigationStateCore(void* navigationState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNavigationStateCore, WINRT_WRAP(void), hstring const&);
            this->shim().SetNavigationStateCore(*reinterpret_cast<hstring const*>(&navigationState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames> : produce_base<D, Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames>
{
    int32_t WINRT_CALL get_KeyFrames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrames, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics>
{
    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrame>
{
    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeyTime));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeyTime const&);
            this->shim().KeyTime(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ObjectKeyFrame), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::ObjectKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics>
{
    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPaneThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPaneThemeTransition>
{
    int32_t WINRT_CALL get_Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Edge, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Edge(Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Edge, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const&);
            this->shim().Edge(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::EdgeTransitionLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics>
{
    int32_t WINRT_CALL get_EdgeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EdgeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EdgeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointAnimation>
{
    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Point> const&);
            this->shim().From(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Point> const&);
            this->shim().To(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_By(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().By());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_By(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(By, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Point> const&);
            this->shim().By(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().EasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().EasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>
{
    int32_t WINRT_CALL get_FromProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ByProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EasingFunctionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EasingFunctionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EasingFunctionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames>
{
    int32_t WINRT_CALL get_KeyFrames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyFrames, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection>(this->shim().KeyFrames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableDependentAnimation(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableDependentAnimation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableDependentAnimation(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimation, WINRT_WRAP(void), bool);
            this->shim().EnableDependentAnimation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics>
{
    int32_t WINRT_CALL get_EnableDependentAnimationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableDependentAnimationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EnableDependentAnimationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrame>
{
    int32_t WINRT_CALL get_Value(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeyTime));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeyTime>(this->shim().KeyTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTime(struct struct_Windows_UI_Xaml_Media_Animation_KeyTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTime, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeyTime const&);
            this->shim().KeyTime(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeyTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::PointKeyFrame), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::PointKeyFrame>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics>
{
    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(void), double);
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopupThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopupThemeTransition>
{
    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(void), double);
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics>
{
    int32_t WINRT_CALL get_FromHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPowerEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPowerEase>
{
    int32_t WINRT_CALL get_Power(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Power, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Power());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Power(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Power, WINRT_WRAP(void), double);
            this->shim().Power(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IPowerEaseStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IPowerEaseStatics>
{
    int32_t WINRT_CALL get_PowerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PowerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IQuadraticEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IQuadraticEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IQuarticEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IQuarticEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IQuinticEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::IQuinticEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IReorderThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IReorderThemeTransition>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>
{
    int32_t WINRT_CALL get_Forever(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Forever, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::RepeatBehavior));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().Forever());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromCount(double count, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromCount, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::RepeatBehavior), double);
            *result = detach_from<Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().FromCount(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromDuration(Windows::Foundation::TimeSpan duration, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromDuration, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::RepeatBehavior), Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().FromDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHasCount(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHasCount, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Animation::RepeatBehavior const&);
            *result = detach_from<bool>(this->shim().GetHasCount(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHasDuration(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHasDuration, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Animation::RepeatBehavior const&);
            *result = detach_from<bool>(this->shim().GetHasDuration(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior target, struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::UI::Xaml::Media::Animation::RepeatBehavior const&, Windows::UI::Xaml::Media::Animation::RepeatBehavior const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&target), *reinterpret_cast<Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(void), double);
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2>
{
    int32_t WINRT_CALL get_IsStaggeringEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStaggeringEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStaggeringEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabled, WINRT_WRAP(void), bool);
            this->shim().IsStaggeringEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2> : produce_base<D, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2>
{
    int32_t WINRT_CALL get_IsStaggeringEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaggeringEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsStaggeringEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISineEase> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISineEase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2>
{
    int32_t WINRT_CALL get_Effect(Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Effect, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect>(this->shim().Effect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Effect(Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Effect, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect const&);
            this->shim().Effect(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2>
{
    int32_t WINRT_CALL get_EffectProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().EffectProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame>
{
    int32_t WINRT_CALL get_KeySpline(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeySpline));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeySpline(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeySpline const&);
            this->shim().KeySpline(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics>
{
    int32_t WINRT_CALL get_KeySplineProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySplineProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame>
{
    int32_t WINRT_CALL get_KeySpline(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeySpline));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeySpline(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeySpline const&);
            this->shim().KeySpline(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics>
{
    int32_t WINRT_CALL get_KeySplineProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySplineProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame>
{
    int32_t WINRT_CALL get_KeySpline(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::KeySpline));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::KeySpline>(this->shim().KeySpline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeySpline(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySpline, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::KeySpline const&);
            this->shim().KeySpline(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::KeySpline const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics>
{
    int32_t WINRT_CALL get_KeySplineProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeySplineProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeySplineProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation>
{
    int32_t WINRT_CALL get_OpenedTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OpenedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().OpenedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OpenedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().OpenedTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ClosedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ClosedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ClosedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ClosedTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ContentTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ContentTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ContentTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedLength(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLength, WINRT_WRAP(void), double);
            this->shim().OpenedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ClosedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedLength(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLength, WINRT_WRAP(void), double);
            this->shim().ClosedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetFromCenter(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenter, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OffsetFromCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OffsetFromCenter(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenter, WINRT_WRAP(void), double);
            this->shim().OffsetFromCenter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirection, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::AnimationDirection));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().ContentTranslationDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirection, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::AnimationDirection const&);
            this->shim().ContentTranslationDirection(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ContentTranslationOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTranslationOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffset, WINRT_WRAP(void), double);
            this->shim().ContentTranslationOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>
{
    int32_t WINRT_CALL get_OpenedTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedLengthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLengthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedLengthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLengthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetFromCenterProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenterProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetFromCenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationDirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation>
{
    int32_t WINRT_CALL get_OpenedTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OpenedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().OpenedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OpenedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().OpenedTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ClosedTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ClosedTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ClosedTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ClosedTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentTargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetName, WINRT_WRAP(void), hstring const&);
            this->shim().ContentTargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ContentTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ContentTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OpenedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpenedLength(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLength, WINRT_WRAP(void), double);
            this->shim().OpenedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ClosedLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosedLength(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLength, WINRT_WRAP(void), double);
            this->shim().ClosedLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetFromCenter(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenter, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().OffsetFromCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OffsetFromCenter(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenter, WINRT_WRAP(void), double);
            this->shim().OffsetFromCenter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirection, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::AnimationDirection));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::AnimationDirection>(this->shim().ContentTranslationDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTranslationDirection(Windows::UI::Xaml::Controls::Primitives::AnimationDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirection, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::AnimationDirection const&);
            this->shim().ContentTranslationDirection(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::AnimationDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ContentTranslationOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentTranslationOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffset, WINRT_WRAP(void), double);
            this->shim().ContentTranslationOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>
{
    int32_t WINRT_CALL get_OpenedTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpenedLengthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenedLengthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpenedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosedLengthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosedLengthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClosedLengthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OffsetFromCenterProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OffsetFromCenterProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OffsetFromCenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationDirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationDirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentTranslationOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentTranslationOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContentTranslationOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IStoryboard> : produce_base<D, Windows::UI::Xaml::Media::Animation::IStoryboard>
{
    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::TimelineCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::TimelineCollection>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Seek(Windows::Foundation::TimeSpan offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Seek, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Seek(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Begin() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Begin, WINRT_WRAP(void));
            this->shim().Begin();
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

    int32_t WINRT_CALL GetCurrentState(Windows::UI::Xaml::Media::Animation::ClockState* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentState, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::ClockState));
            *result = detach_from<Windows::UI::Xaml::Media::Animation::ClockState>(this->shim().GetCurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentTime(Windows::Foundation::TimeSpan* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *result = detach_from<Windows::Foundation::TimeSpan>(this->shim().GetCurrentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SeekAlignedToLastTick(Windows::Foundation::TimeSpan offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeekAlignedToLastTick, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().SeekAlignedToLastTick(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SkipToFill() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkipToFill, WINRT_WRAP(void));
            this->shim().SkipToFill();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::IStoryboardStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>
{
    int32_t WINRT_CALL get_TargetPropertyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetPropertyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetPropertyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTargetProperty(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTargetProperty, WINRT_WRAP(hstring), Windows::UI::Xaml::Media::Animation::Timeline const&);
            *result = detach_from<hstring>(this->shim().GetTargetProperty(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Timeline const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTargetProperty(void* element, void* path) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTargetProperty, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Timeline const&, hstring const&);
            this->shim().SetTargetProperty(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Timeline const*>(&element), *reinterpret_cast<hstring const*>(&path));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTargetName(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTargetName, WINRT_WRAP(hstring), Windows::UI::Xaml::Media::Animation::Timeline const&);
            *result = detach_from<hstring>(this->shim().GetTargetName(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Timeline const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTargetName(void* element, void* name) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTargetName, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Timeline const&, hstring const&);
            this->shim().SetTargetName(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Timeline const*>(&element), *reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTarget(void* timeline, void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTarget, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Timeline const&, Windows::UI::Xaml::DependencyObject const&);
            this->shim().SetTarget(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Timeline const*>(&timeline), *reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().FromHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FromVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FromVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffset, WINRT_WRAP(void), double);
            this->shim().FromVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FromVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FromVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation>
{
    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ToHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().ToHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ToVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToVerticalOffset, WINRT_WRAP(void), double);
            this->shim().ToVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics>
{
    int32_t WINRT_CALL get_TargetNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TargetNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ToVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ITimeline> : produce_base<D, Windows::UI::Xaml::Media::Animation::ITimeline>
{
    int32_t WINRT_CALL get_AutoReverse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoReverse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoReverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoReverse(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoReverse, WINRT_WRAP(void), bool);
            this->shim().AutoReverse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeginTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().BeginTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BeginTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().BeginTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(struct struct_Windows_UI_Xaml_Duration* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::UI::Xaml::Duration));
            *value = detach_from<Windows::UI::Xaml::Duration>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(struct struct_Windows_UI_Xaml_Duration value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::UI::Xaml::Duration const&);
            this->shim().Duration(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpeedRatio(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedRatio, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SpeedRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpeedRatio(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedRatio, WINRT_WRAP(void), double);
            this->shim().SpeedRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillBehavior(Windows::UI::Xaml::Media::Animation::FillBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillBehavior, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::FillBehavior));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::FillBehavior>(this->shim().FillBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FillBehavior(Windows::UI::Xaml::Media::Animation::FillBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillBehavior, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::FillBehavior const&);
            this->shim().FillBehavior(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::FillBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepeatBehavior(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatBehavior, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::RepeatBehavior));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::RepeatBehavior>(this->shim().RepeatBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RepeatBehavior(struct struct_Windows_UI_Xaml_Media_Animation_RepeatBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatBehavior, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::RepeatBehavior const&);
            this->shim().RepeatBehavior(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::RepeatBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
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
struct produce<D, Windows::UI::Xaml::Media::Animation::ITimelineFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::ITimelineFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::Timeline), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Animation::Timeline>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ITimelineStatics> : produce_base<D, Windows::UI::Xaml::Media::Animation::ITimelineStatics>
{
    int32_t WINRT_CALL get_AllowDependentAnimations(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowDependentAnimations, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowDependentAnimations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowDependentAnimations(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowDependentAnimations, WINRT_WRAP(void), bool);
            this->shim().AllowDependentAnimations(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoReverseProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoReverseProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AutoReverseProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeginTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginTimeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BeginTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DurationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DurationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DurationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpeedRatioProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedRatioProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SpeedRatioProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillBehaviorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillBehaviorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FillBehaviorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RepeatBehaviorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatBehaviorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RepeatBehaviorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ITransition> : produce_base<D, Windows::UI::Xaml::Media::Animation::ITransition>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Animation::ITransitionFactory> : produce_base<D, Windows::UI::Xaml::Media::Animation::ITransitionFactory>
{};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides>
{
    hstring GetNavigationStateCore()
    {
        Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetNavigationStateCore();
        }
        return this->shim().GetNavigationStateCore();
    }
    void SetNavigationStateCore(hstring const& navigationState)
    {
        Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.SetNavigationStateCore(navigationState);
        }
        return this->shim().SetNavigationStateCore(navigationState);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Animation {

inline AddDeleteThemeTransition::AddDeleteThemeTransition() :
    AddDeleteThemeTransition(impl::call_factory<AddDeleteThemeTransition>([](auto&& f) { return f.template ActivateInstance<AddDeleteThemeTransition>(); }))
{}

inline BackEase::BackEase() :
    BackEase(impl::call_factory<BackEase>([](auto&& f) { return f.template ActivateInstance<BackEase>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty BackEase::AmplitudeProperty()
{
    return impl::call_factory<BackEase, Windows::UI::Xaml::Media::Animation::IBackEaseStatics>([&](auto&& f) { return f.AmplitudeProperty(); });
}

inline BasicConnectedAnimationConfiguration::BasicConnectedAnimationConfiguration()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<BasicConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline BeginStoryboard::BeginStoryboard() :
    BeginStoryboard(impl::call_factory<BeginStoryboard>([](auto&& f) { return f.template ActivateInstance<BeginStoryboard>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty BeginStoryboard::StoryboardProperty()
{
    return impl::call_factory<BeginStoryboard, Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics>([&](auto&& f) { return f.StoryboardProperty(); });
}

inline BounceEase::BounceEase() :
    BounceEase(impl::call_factory<BounceEase>([](auto&& f) { return f.template ActivateInstance<BounceEase>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty BounceEase::BouncesProperty()
{
    return impl::call_factory<BounceEase, Windows::UI::Xaml::Media::Animation::IBounceEaseStatics>([&](auto&& f) { return f.BouncesProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BounceEase::BouncinessProperty()
{
    return impl::call_factory<BounceEase, Windows::UI::Xaml::Media::Animation::IBounceEaseStatics>([&](auto&& f) { return f.BouncinessProperty(); });
}

inline CircleEase::CircleEase() :
    CircleEase(impl::call_factory<CircleEase>([](auto&& f) { return f.template ActivateInstance<CircleEase>(); }))
{}

inline ColorAnimation::ColorAnimation() :
    ColorAnimation(impl::call_factory<ColorAnimation>([](auto&& f) { return f.template ActivateInstance<ColorAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ColorAnimation::FromProperty()
{
    return impl::call_factory<ColorAnimation, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>([&](auto&& f) { return f.FromProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorAnimation::ToProperty()
{
    return impl::call_factory<ColorAnimation, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>([&](auto&& f) { return f.ToProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorAnimation::ByProperty()
{
    return impl::call_factory<ColorAnimation, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>([&](auto&& f) { return f.ByProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorAnimation::EasingFunctionProperty()
{
    return impl::call_factory<ColorAnimation, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorAnimation::EnableDependentAnimationProperty()
{
    return impl::call_factory<ColorAnimation, Windows::UI::Xaml::Media::Animation::IColorAnimationStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline ColorAnimationUsingKeyFrames::ColorAnimationUsingKeyFrames() :
    ColorAnimationUsingKeyFrames(impl::call_factory<ColorAnimationUsingKeyFrames>([](auto&& f) { return f.template ActivateInstance<ColorAnimationUsingKeyFrames>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ColorAnimationUsingKeyFrames::EnableDependentAnimationProperty()
{
    return impl::call_factory<ColorAnimationUsingKeyFrames, Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorKeyFrame::ValueProperty()
{
    return impl::call_factory<ColorKeyFrame, Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ColorKeyFrame::KeyTimeProperty()
{
    return impl::call_factory<ColorKeyFrame, Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics>([&](auto&& f) { return f.KeyTimeProperty(); });
}

inline ColorKeyFrameCollection::ColorKeyFrameCollection() :
    ColorKeyFrameCollection(impl::call_factory<ColorKeyFrameCollection>([](auto&& f) { return f.template ActivateInstance<ColorKeyFrameCollection>(); }))
{}

inline CommonNavigationTransitionInfo::CommonNavigationTransitionInfo() :
    CommonNavigationTransitionInfo(impl::call_factory<CommonNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<CommonNavigationTransitionInfo>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty CommonNavigationTransitionInfo::IsStaggeringEnabledProperty()
{
    return impl::call_factory<CommonNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>([&](auto&& f) { return f.IsStaggeringEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CommonNavigationTransitionInfo::IsStaggerElementProperty()
{
    return impl::call_factory<CommonNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>([&](auto&& f) { return f.IsStaggerElementProperty(); });
}

inline bool CommonNavigationTransitionInfo::GetIsStaggerElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<CommonNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>([&](auto&& f) { return f.GetIsStaggerElement(element); });
}

inline void CommonNavigationTransitionInfo::SetIsStaggerElement(Windows::UI::Xaml::UIElement const& element, bool value)
{
    impl::call_factory<CommonNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics>([&](auto&& f) { return f.SetIsStaggerElement(element, value); });
}

inline Windows::UI::Xaml::Media::Animation::ConnectedAnimationService ConnectedAnimationService::GetForCurrentView()
{
    return impl::call_factory<ConnectedAnimationService, Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline ContentThemeTransition::ContentThemeTransition() :
    ContentThemeTransition(impl::call_factory<ContentThemeTransition>([](auto&& f) { return f.template ActivateInstance<ContentThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ContentThemeTransition::HorizontalOffsetProperty()
{
    return impl::call_factory<ContentThemeTransition, Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics>([&](auto&& f) { return f.HorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContentThemeTransition::VerticalOffsetProperty()
{
    return impl::call_factory<ContentThemeTransition, Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics>([&](auto&& f) { return f.VerticalOffsetProperty(); });
}

inline ContinuumNavigationTransitionInfo::ContinuumNavigationTransitionInfo() :
    ContinuumNavigationTransitionInfo(impl::call_factory<ContinuumNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<ContinuumNavigationTransitionInfo>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ContinuumNavigationTransitionInfo::ExitElementProperty()
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.ExitElementProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ContinuumNavigationTransitionInfo::IsEntranceElementProperty()
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.IsEntranceElementProperty(); });
}

inline bool ContinuumNavigationTransitionInfo::GetIsEntranceElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.GetIsEntranceElement(element); });
}

inline void ContinuumNavigationTransitionInfo::SetIsEntranceElement(Windows::UI::Xaml::UIElement const& element, bool value)
{
    impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.SetIsEntranceElement(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty ContinuumNavigationTransitionInfo::IsExitElementProperty()
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.IsExitElementProperty(); });
}

inline bool ContinuumNavigationTransitionInfo::GetIsExitElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.GetIsExitElement(element); });
}

inline void ContinuumNavigationTransitionInfo::SetIsExitElement(Windows::UI::Xaml::UIElement const& element, bool value)
{
    impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.SetIsExitElement(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty ContinuumNavigationTransitionInfo::ExitElementContainerProperty()
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.ExitElementContainerProperty(); });
}

inline bool ContinuumNavigationTransitionInfo::GetExitElementContainer(Windows::UI::Xaml::Controls::ListViewBase const& element)
{
    return impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.GetExitElementContainer(element); });
}

inline void ContinuumNavigationTransitionInfo::SetExitElementContainer(Windows::UI::Xaml::Controls::ListViewBase const& element, bool value)
{
    impl::call_factory<ContinuumNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics>([&](auto&& f) { return f.SetExitElementContainer(element, value); });
}

inline CubicEase::CubicEase() :
    CubicEase(impl::call_factory<CubicEase>([](auto&& f) { return f.template ActivateInstance<CubicEase>(); }))
{}

inline DirectConnectedAnimationConfiguration::DirectConnectedAnimationConfiguration()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DirectConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline DiscreteColorKeyFrame::DiscreteColorKeyFrame() :
    DiscreteColorKeyFrame(impl::call_factory<DiscreteColorKeyFrame>([](auto&& f) { return f.template ActivateInstance<DiscreteColorKeyFrame>(); }))
{}

inline DiscreteDoubleKeyFrame::DiscreteDoubleKeyFrame() :
    DiscreteDoubleKeyFrame(impl::call_factory<DiscreteDoubleKeyFrame>([](auto&& f) { return f.template ActivateInstance<DiscreteDoubleKeyFrame>(); }))
{}

inline DiscreteObjectKeyFrame::DiscreteObjectKeyFrame() :
    DiscreteObjectKeyFrame(impl::call_factory<DiscreteObjectKeyFrame>([](auto&& f) { return f.template ActivateInstance<DiscreteObjectKeyFrame>(); }))
{}

inline DiscretePointKeyFrame::DiscretePointKeyFrame() :
    DiscretePointKeyFrame(impl::call_factory<DiscretePointKeyFrame>([](auto&& f) { return f.template ActivateInstance<DiscretePointKeyFrame>(); }))
{}

inline DoubleAnimation::DoubleAnimation() :
    DoubleAnimation(impl::call_factory<DoubleAnimation>([](auto&& f) { return f.template ActivateInstance<DoubleAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimation::FromProperty()
{
    return impl::call_factory<DoubleAnimation, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>([&](auto&& f) { return f.FromProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimation::ToProperty()
{
    return impl::call_factory<DoubleAnimation, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>([&](auto&& f) { return f.ToProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimation::ByProperty()
{
    return impl::call_factory<DoubleAnimation, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>([&](auto&& f) { return f.ByProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimation::EasingFunctionProperty()
{
    return impl::call_factory<DoubleAnimation, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimation::EnableDependentAnimationProperty()
{
    return impl::call_factory<DoubleAnimation, Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline DoubleAnimationUsingKeyFrames::DoubleAnimationUsingKeyFrames() :
    DoubleAnimationUsingKeyFrames(impl::call_factory<DoubleAnimationUsingKeyFrames>([](auto&& f) { return f.template ActivateInstance<DoubleAnimationUsingKeyFrames>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DoubleAnimationUsingKeyFrames::EnableDependentAnimationProperty()
{
    return impl::call_factory<DoubleAnimationUsingKeyFrames, Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleKeyFrame::ValueProperty()
{
    return impl::call_factory<DoubleKeyFrame, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DoubleKeyFrame::KeyTimeProperty()
{
    return impl::call_factory<DoubleKeyFrame, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics>([&](auto&& f) { return f.KeyTimeProperty(); });
}

inline DoubleKeyFrameCollection::DoubleKeyFrameCollection() :
    DoubleKeyFrameCollection(impl::call_factory<DoubleKeyFrameCollection>([](auto&& f) { return f.template ActivateInstance<DoubleKeyFrameCollection>(); }))
{}

inline DragItemThemeAnimation::DragItemThemeAnimation() :
    DragItemThemeAnimation(impl::call_factory<DragItemThemeAnimation>([](auto&& f) { return f.template ActivateInstance<DragItemThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DragItemThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<DragItemThemeAnimation, Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline DragOverThemeAnimation::DragOverThemeAnimation() :
    DragOverThemeAnimation(impl::call_factory<DragOverThemeAnimation>([](auto&& f) { return f.template ActivateInstance<DragOverThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DragOverThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<DragOverThemeAnimation, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DragOverThemeAnimation::ToOffsetProperty()
{
    return impl::call_factory<DragOverThemeAnimation, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics>([&](auto&& f) { return f.ToOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DragOverThemeAnimation::DirectionProperty()
{
    return impl::call_factory<DragOverThemeAnimation, Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics>([&](auto&& f) { return f.DirectionProperty(); });
}

inline DrillInNavigationTransitionInfo::DrillInNavigationTransitionInfo() :
    DrillInNavigationTransitionInfo(impl::call_factory<DrillInNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<DrillInNavigationTransitionInfo>(); }))
{}

inline DrillInThemeAnimation::DrillInThemeAnimation() :
    DrillInThemeAnimation(impl::call_factory<DrillInThemeAnimation>([](auto&& f) { return f.template ActivateInstance<DrillInThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DrillInThemeAnimation::EntranceTargetNameProperty()
{
    return impl::call_factory<DrillInThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>([&](auto&& f) { return f.EntranceTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillInThemeAnimation::EntranceTargetProperty()
{
    return impl::call_factory<DrillInThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>([&](auto&& f) { return f.EntranceTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillInThemeAnimation::ExitTargetNameProperty()
{
    return impl::call_factory<DrillInThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>([&](auto&& f) { return f.ExitTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillInThemeAnimation::ExitTargetProperty()
{
    return impl::call_factory<DrillInThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics>([&](auto&& f) { return f.ExitTargetProperty(); });
}

inline DrillOutThemeAnimation::DrillOutThemeAnimation() :
    DrillOutThemeAnimation(impl::call_factory<DrillOutThemeAnimation>([](auto&& f) { return f.template ActivateInstance<DrillOutThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DrillOutThemeAnimation::EntranceTargetNameProperty()
{
    return impl::call_factory<DrillOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>([&](auto&& f) { return f.EntranceTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillOutThemeAnimation::EntranceTargetProperty()
{
    return impl::call_factory<DrillOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>([&](auto&& f) { return f.EntranceTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillOutThemeAnimation::ExitTargetNameProperty()
{
    return impl::call_factory<DrillOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>([&](auto&& f) { return f.ExitTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty DrillOutThemeAnimation::ExitTargetProperty()
{
    return impl::call_factory<DrillOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics>([&](auto&& f) { return f.ExitTargetProperty(); });
}

inline DropTargetItemThemeAnimation::DropTargetItemThemeAnimation() :
    DropTargetItemThemeAnimation(impl::call_factory<DropTargetItemThemeAnimation>([](auto&& f) { return f.template ActivateInstance<DropTargetItemThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty DropTargetItemThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<DropTargetItemThemeAnimation, Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline EasingColorKeyFrame::EasingColorKeyFrame() :
    EasingColorKeyFrame(impl::call_factory<EasingColorKeyFrame>([](auto&& f) { return f.template ActivateInstance<EasingColorKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EasingColorKeyFrame::EasingFunctionProperty()
{
    return impl::call_factory<EasingColorKeyFrame, Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline EasingDoubleKeyFrame::EasingDoubleKeyFrame() :
    EasingDoubleKeyFrame(impl::call_factory<EasingDoubleKeyFrame>([](auto&& f) { return f.template ActivateInstance<EasingDoubleKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EasingDoubleKeyFrame::EasingFunctionProperty()
{
    return impl::call_factory<EasingDoubleKeyFrame, Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty EasingFunctionBase::EasingModeProperty()
{
    return impl::call_factory<EasingFunctionBase, Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics>([&](auto&& f) { return f.EasingModeProperty(); });
}

inline EasingPointKeyFrame::EasingPointKeyFrame() :
    EasingPointKeyFrame(impl::call_factory<EasingPointKeyFrame>([](auto&& f) { return f.template ActivateInstance<EasingPointKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EasingPointKeyFrame::EasingFunctionProperty()
{
    return impl::call_factory<EasingPointKeyFrame, Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline EdgeUIThemeTransition::EdgeUIThemeTransition() :
    EdgeUIThemeTransition(impl::call_factory<EdgeUIThemeTransition>([](auto&& f) { return f.template ActivateInstance<EdgeUIThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EdgeUIThemeTransition::EdgeProperty()
{
    return impl::call_factory<EdgeUIThemeTransition, Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics>([&](auto&& f) { return f.EdgeProperty(); });
}

inline ElasticEase::ElasticEase() :
    ElasticEase(impl::call_factory<ElasticEase>([](auto&& f) { return f.template ActivateInstance<ElasticEase>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ElasticEase::OscillationsProperty()
{
    return impl::call_factory<ElasticEase, Windows::UI::Xaml::Media::Animation::IElasticEaseStatics>([&](auto&& f) { return f.OscillationsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ElasticEase::SpringinessProperty()
{
    return impl::call_factory<ElasticEase, Windows::UI::Xaml::Media::Animation::IElasticEaseStatics>([&](auto&& f) { return f.SpringinessProperty(); });
}

inline EntranceNavigationTransitionInfo::EntranceNavigationTransitionInfo() :
    EntranceNavigationTransitionInfo(impl::call_factory<EntranceNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<EntranceNavigationTransitionInfo>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EntranceNavigationTransitionInfo::IsTargetElementProperty()
{
    return impl::call_factory<EntranceNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics>([&](auto&& f) { return f.IsTargetElementProperty(); });
}

inline bool EntranceNavigationTransitionInfo::GetIsTargetElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<EntranceNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics>([&](auto&& f) { return f.GetIsTargetElement(element); });
}

inline void EntranceNavigationTransitionInfo::SetIsTargetElement(Windows::UI::Xaml::UIElement const& element, bool value)
{
    impl::call_factory<EntranceNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics>([&](auto&& f) { return f.SetIsTargetElement(element, value); });
}

inline EntranceThemeTransition::EntranceThemeTransition() :
    EntranceThemeTransition(impl::call_factory<EntranceThemeTransition>([](auto&& f) { return f.template ActivateInstance<EntranceThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty EntranceThemeTransition::FromHorizontalOffsetProperty()
{
    return impl::call_factory<EntranceThemeTransition, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics>([&](auto&& f) { return f.FromHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty EntranceThemeTransition::FromVerticalOffsetProperty()
{
    return impl::call_factory<EntranceThemeTransition, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics>([&](auto&& f) { return f.FromVerticalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty EntranceThemeTransition::IsStaggeringEnabledProperty()
{
    return impl::call_factory<EntranceThemeTransition, Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics>([&](auto&& f) { return f.IsStaggeringEnabledProperty(); });
}

inline ExponentialEase::ExponentialEase() :
    ExponentialEase(impl::call_factory<ExponentialEase>([](auto&& f) { return f.template ActivateInstance<ExponentialEase>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ExponentialEase::ExponentProperty()
{
    return impl::call_factory<ExponentialEase, Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics>([&](auto&& f) { return f.ExponentProperty(); });
}

inline FadeInThemeAnimation::FadeInThemeAnimation() :
    FadeInThemeAnimation(impl::call_factory<FadeInThemeAnimation>([](auto&& f) { return f.template ActivateInstance<FadeInThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty FadeInThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<FadeInThemeAnimation, Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline FadeOutThemeAnimation::FadeOutThemeAnimation() :
    FadeOutThemeAnimation(impl::call_factory<FadeOutThemeAnimation>([](auto&& f) { return f.template ActivateInstance<FadeOutThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty FadeOutThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<FadeOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline GravityConnectedAnimationConfiguration::GravityConnectedAnimationConfiguration()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GravityConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline KeySpline::KeySpline() :
    KeySpline(impl::call_factory<KeySpline>([](auto&& f) { return f.template ActivateInstance<KeySpline>(); }))
{}

inline Windows::UI::Xaml::Media::Animation::KeyTime KeyTimeHelper::FromTimeSpan(Windows::Foundation::TimeSpan const& timeSpan)
{
    return impl::call_factory<KeyTimeHelper, Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics>([&](auto&& f) { return f.FromTimeSpan(timeSpan); });
}

inline LinearColorKeyFrame::LinearColorKeyFrame() :
    LinearColorKeyFrame(impl::call_factory<LinearColorKeyFrame>([](auto&& f) { return f.template ActivateInstance<LinearColorKeyFrame>(); }))
{}

inline LinearDoubleKeyFrame::LinearDoubleKeyFrame() :
    LinearDoubleKeyFrame(impl::call_factory<LinearDoubleKeyFrame>([](auto&& f) { return f.template ActivateInstance<LinearDoubleKeyFrame>(); }))
{}

inline LinearPointKeyFrame::LinearPointKeyFrame() :
    LinearPointKeyFrame(impl::call_factory<LinearPointKeyFrame>([](auto&& f) { return f.template ActivateInstance<LinearPointKeyFrame>(); }))
{}

inline NavigationThemeTransition::NavigationThemeTransition() :
    NavigationThemeTransition(impl::call_factory<NavigationThemeTransition>([](auto&& f) { return f.template ActivateInstance<NavigationThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty NavigationThemeTransition::DefaultNavigationTransitionInfoProperty()
{
    return impl::call_factory<NavigationThemeTransition, Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics>([&](auto&& f) { return f.DefaultNavigationTransitionInfoProperty(); });
}

inline ObjectAnimationUsingKeyFrames::ObjectAnimationUsingKeyFrames() :
    ObjectAnimationUsingKeyFrames(impl::call_factory<ObjectAnimationUsingKeyFrames>([](auto&& f) { return f.template ActivateInstance<ObjectAnimationUsingKeyFrames>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty ObjectAnimationUsingKeyFrames::EnableDependentAnimationProperty()
{
    return impl::call_factory<ObjectAnimationUsingKeyFrames, Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ObjectKeyFrame::ValueProperty()
{
    return impl::call_factory<ObjectKeyFrame, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty ObjectKeyFrame::KeyTimeProperty()
{
    return impl::call_factory<ObjectKeyFrame, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics>([&](auto&& f) { return f.KeyTimeProperty(); });
}

inline ObjectKeyFrameCollection::ObjectKeyFrameCollection() :
    ObjectKeyFrameCollection(impl::call_factory<ObjectKeyFrameCollection>([](auto&& f) { return f.template ActivateInstance<ObjectKeyFrameCollection>(); }))
{}

inline PaneThemeTransition::PaneThemeTransition() :
    PaneThemeTransition(impl::call_factory<PaneThemeTransition>([](auto&& f) { return f.template ActivateInstance<PaneThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PaneThemeTransition::EdgeProperty()
{
    return impl::call_factory<PaneThemeTransition, Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics>([&](auto&& f) { return f.EdgeProperty(); });
}

inline PointAnimation::PointAnimation() :
    PointAnimation(impl::call_factory<PointAnimation>([](auto&& f) { return f.template ActivateInstance<PointAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PointAnimation::FromProperty()
{
    return impl::call_factory<PointAnimation, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>([&](auto&& f) { return f.FromProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointAnimation::ToProperty()
{
    return impl::call_factory<PointAnimation, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>([&](auto&& f) { return f.ToProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointAnimation::ByProperty()
{
    return impl::call_factory<PointAnimation, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>([&](auto&& f) { return f.ByProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointAnimation::EasingFunctionProperty()
{
    return impl::call_factory<PointAnimation, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>([&](auto&& f) { return f.EasingFunctionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointAnimation::EnableDependentAnimationProperty()
{
    return impl::call_factory<PointAnimation, Windows::UI::Xaml::Media::Animation::IPointAnimationStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline PointAnimationUsingKeyFrames::PointAnimationUsingKeyFrames() :
    PointAnimationUsingKeyFrames(impl::call_factory<PointAnimationUsingKeyFrames>([](auto&& f) { return f.template ActivateInstance<PointAnimationUsingKeyFrames>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PointAnimationUsingKeyFrames::EnableDependentAnimationProperty()
{
    return impl::call_factory<PointAnimationUsingKeyFrames, Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics>([&](auto&& f) { return f.EnableDependentAnimationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointKeyFrame::ValueProperty()
{
    return impl::call_factory<PointKeyFrame, Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PointKeyFrame::KeyTimeProperty()
{
    return impl::call_factory<PointKeyFrame, Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics>([&](auto&& f) { return f.KeyTimeProperty(); });
}

inline PointKeyFrameCollection::PointKeyFrameCollection() :
    PointKeyFrameCollection(impl::call_factory<PointKeyFrameCollection>([](auto&& f) { return f.template ActivateInstance<PointKeyFrameCollection>(); }))
{}

inline PointerDownThemeAnimation::PointerDownThemeAnimation() :
    PointerDownThemeAnimation(impl::call_factory<PointerDownThemeAnimation>([](auto&& f) { return f.template ActivateInstance<PointerDownThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PointerDownThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<PointerDownThemeAnimation, Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline PointerUpThemeAnimation::PointerUpThemeAnimation() :
    PointerUpThemeAnimation(impl::call_factory<PointerUpThemeAnimation>([](auto&& f) { return f.template ActivateInstance<PointerUpThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PointerUpThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<PointerUpThemeAnimation, Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline PopInThemeAnimation::PopInThemeAnimation() :
    PopInThemeAnimation(impl::call_factory<PopInThemeAnimation>([](auto&& f) { return f.template ActivateInstance<PopInThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PopInThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<PopInThemeAnimation, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PopInThemeAnimation::FromHorizontalOffsetProperty()
{
    return impl::call_factory<PopInThemeAnimation, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics>([&](auto&& f) { return f.FromHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PopInThemeAnimation::FromVerticalOffsetProperty()
{
    return impl::call_factory<PopInThemeAnimation, Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics>([&](auto&& f) { return f.FromVerticalOffsetProperty(); });
}

inline PopOutThemeAnimation::PopOutThemeAnimation() :
    PopOutThemeAnimation(impl::call_factory<PopOutThemeAnimation>([](auto&& f) { return f.template ActivateInstance<PopOutThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PopOutThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<PopOutThemeAnimation, Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline PopupThemeTransition::PopupThemeTransition() :
    PopupThemeTransition(impl::call_factory<PopupThemeTransition>([](auto&& f) { return f.template ActivateInstance<PopupThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PopupThemeTransition::FromHorizontalOffsetProperty()
{
    return impl::call_factory<PopupThemeTransition, Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics>([&](auto&& f) { return f.FromHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty PopupThemeTransition::FromVerticalOffsetProperty()
{
    return impl::call_factory<PopupThemeTransition, Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics>([&](auto&& f) { return f.FromVerticalOffsetProperty(); });
}

inline PowerEase::PowerEase() :
    PowerEase(impl::call_factory<PowerEase>([](auto&& f) { return f.template ActivateInstance<PowerEase>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty PowerEase::PowerProperty()
{
    return impl::call_factory<PowerEase, Windows::UI::Xaml::Media::Animation::IPowerEaseStatics>([&](auto&& f) { return f.PowerProperty(); });
}

inline QuadraticEase::QuadraticEase() :
    QuadraticEase(impl::call_factory<QuadraticEase>([](auto&& f) { return f.template ActivateInstance<QuadraticEase>(); }))
{}

inline QuarticEase::QuarticEase() :
    QuarticEase(impl::call_factory<QuarticEase>([](auto&& f) { return f.template ActivateInstance<QuarticEase>(); }))
{}

inline QuinticEase::QuinticEase() :
    QuinticEase(impl::call_factory<QuinticEase>([](auto&& f) { return f.template ActivateInstance<QuinticEase>(); }))
{}

inline ReorderThemeTransition::ReorderThemeTransition() :
    ReorderThemeTransition(impl::call_factory<ReorderThemeTransition>([](auto&& f) { return f.template ActivateInstance<ReorderThemeTransition>(); }))
{}

inline Windows::UI::Xaml::Media::Animation::RepeatBehavior RepeatBehaviorHelper::Forever()
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.Forever(); });
}

inline Windows::UI::Xaml::Media::Animation::RepeatBehavior RepeatBehaviorHelper::FromCount(double count)
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.FromCount(count); });
}

inline Windows::UI::Xaml::Media::Animation::RepeatBehavior RepeatBehaviorHelper::FromDuration(Windows::Foundation::TimeSpan const& duration)
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.FromDuration(duration); });
}

inline bool RepeatBehaviorHelper::GetHasCount(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target)
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.GetHasCount(target); });
}

inline bool RepeatBehaviorHelper::GetHasDuration(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target)
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.GetHasDuration(target); });
}

inline bool RepeatBehaviorHelper::Equals(Windows::UI::Xaml::Media::Animation::RepeatBehavior const& target, Windows::UI::Xaml::Media::Animation::RepeatBehavior const& value)
{
    return impl::call_factory<RepeatBehaviorHelper, Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline RepositionThemeAnimation::RepositionThemeAnimation() :
    RepositionThemeAnimation(impl::call_factory<RepositionThemeAnimation>([](auto&& f) { return f.template ActivateInstance<RepositionThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RepositionThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<RepositionThemeAnimation, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RepositionThemeAnimation::FromHorizontalOffsetProperty()
{
    return impl::call_factory<RepositionThemeAnimation, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics>([&](auto&& f) { return f.FromHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RepositionThemeAnimation::FromVerticalOffsetProperty()
{
    return impl::call_factory<RepositionThemeAnimation, Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics>([&](auto&& f) { return f.FromVerticalOffsetProperty(); });
}

inline RepositionThemeTransition::RepositionThemeTransition() :
    RepositionThemeTransition(impl::call_factory<RepositionThemeTransition>([](auto&& f) { return f.template ActivateInstance<RepositionThemeTransition>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RepositionThemeTransition::IsStaggeringEnabledProperty()
{
    return impl::call_factory<RepositionThemeTransition, Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2>([&](auto&& f) { return f.IsStaggeringEnabledProperty(); });
}

inline SineEase::SineEase() :
    SineEase(impl::call_factory<SineEase>([](auto&& f) { return f.template ActivateInstance<SineEase>(); }))
{}

inline SlideNavigationTransitionInfo::SlideNavigationTransitionInfo() :
    SlideNavigationTransitionInfo(impl::call_factory<SlideNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<SlideNavigationTransitionInfo>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SlideNavigationTransitionInfo::EffectProperty()
{
    return impl::call_factory<SlideNavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2>([&](auto&& f) { return f.EffectProperty(); });
}

inline SplineColorKeyFrame::SplineColorKeyFrame() :
    SplineColorKeyFrame(impl::call_factory<SplineColorKeyFrame>([](auto&& f) { return f.template ActivateInstance<SplineColorKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SplineColorKeyFrame::KeySplineProperty()
{
    return impl::call_factory<SplineColorKeyFrame, Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics>([&](auto&& f) { return f.KeySplineProperty(); });
}

inline SplineDoubleKeyFrame::SplineDoubleKeyFrame() :
    SplineDoubleKeyFrame(impl::call_factory<SplineDoubleKeyFrame>([](auto&& f) { return f.template ActivateInstance<SplineDoubleKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SplineDoubleKeyFrame::KeySplineProperty()
{
    return impl::call_factory<SplineDoubleKeyFrame, Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics>([&](auto&& f) { return f.KeySplineProperty(); });
}

inline SplinePointKeyFrame::SplinePointKeyFrame() :
    SplinePointKeyFrame(impl::call_factory<SplinePointKeyFrame>([](auto&& f) { return f.template ActivateInstance<SplinePointKeyFrame>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SplinePointKeyFrame::KeySplineProperty()
{
    return impl::call_factory<SplinePointKeyFrame, Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics>([&](auto&& f) { return f.KeySplineProperty(); });
}

inline SplitCloseThemeAnimation::SplitCloseThemeAnimation() :
    SplitCloseThemeAnimation(impl::call_factory<SplitCloseThemeAnimation>([](auto&& f) { return f.template ActivateInstance<SplitCloseThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::OpenedTargetNameProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.OpenedTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::OpenedTargetProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.OpenedTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ClosedTargetNameProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ClosedTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ClosedTargetProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ClosedTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ContentTargetNameProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ContentTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ContentTargetProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ContentTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::OpenedLengthProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.OpenedLengthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ClosedLengthProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ClosedLengthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::OffsetFromCenterProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.OffsetFromCenterProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ContentTranslationDirectionProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ContentTranslationDirectionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitCloseThemeAnimation::ContentTranslationOffsetProperty()
{
    return impl::call_factory<SplitCloseThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics>([&](auto&& f) { return f.ContentTranslationOffsetProperty(); });
}

inline SplitOpenThemeAnimation::SplitOpenThemeAnimation() :
    SplitOpenThemeAnimation(impl::call_factory<SplitOpenThemeAnimation>([](auto&& f) { return f.template ActivateInstance<SplitOpenThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::OpenedTargetNameProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.OpenedTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::OpenedTargetProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.OpenedTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ClosedTargetNameProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ClosedTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ClosedTargetProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ClosedTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ContentTargetNameProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ContentTargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ContentTargetProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ContentTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::OpenedLengthProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.OpenedLengthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ClosedLengthProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ClosedLengthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::OffsetFromCenterProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.OffsetFromCenterProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ContentTranslationDirectionProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ContentTranslationDirectionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SplitOpenThemeAnimation::ContentTranslationOffsetProperty()
{
    return impl::call_factory<SplitOpenThemeAnimation, Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics>([&](auto&& f) { return f.ContentTranslationOffsetProperty(); });
}

inline Storyboard::Storyboard() :
    Storyboard(impl::call_factory<Storyboard>([](auto&& f) { return f.template ActivateInstance<Storyboard>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty Storyboard::TargetPropertyProperty()
{
    return impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.TargetPropertyProperty(); });
}

inline hstring Storyboard::GetTargetProperty(Windows::UI::Xaml::Media::Animation::Timeline const& element)
{
    return impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.GetTargetProperty(element); });
}

inline void Storyboard::SetTargetProperty(Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& path)
{
    impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.SetTargetProperty(element, path); });
}

inline Windows::UI::Xaml::DependencyProperty Storyboard::TargetNameProperty()
{
    return impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline hstring Storyboard::GetTargetName(Windows::UI::Xaml::Media::Animation::Timeline const& element)
{
    return impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.GetTargetName(element); });
}

inline void Storyboard::SetTargetName(Windows::UI::Xaml::Media::Animation::Timeline const& element, param::hstring const& name)
{
    impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.SetTargetName(element, name); });
}

inline void Storyboard::SetTarget(Windows::UI::Xaml::Media::Animation::Timeline const& timeline, Windows::UI::Xaml::DependencyObject const& target)
{
    impl::call_factory<Storyboard, Windows::UI::Xaml::Media::Animation::IStoryboardStatics>([&](auto&& f) { return f.SetTarget(timeline, target); });
}

inline SuppressNavigationTransitionInfo::SuppressNavigationTransitionInfo() :
    SuppressNavigationTransitionInfo(impl::call_factory<SuppressNavigationTransitionInfo>([](auto&& f) { return f.template ActivateInstance<SuppressNavigationTransitionInfo>(); }))
{}

inline SwipeBackThemeAnimation::SwipeBackThemeAnimation() :
    SwipeBackThemeAnimation(impl::call_factory<SwipeBackThemeAnimation>([](auto&& f) { return f.template ActivateInstance<SwipeBackThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SwipeBackThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<SwipeBackThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SwipeBackThemeAnimation::FromHorizontalOffsetProperty()
{
    return impl::call_factory<SwipeBackThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics>([&](auto&& f) { return f.FromHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SwipeBackThemeAnimation::FromVerticalOffsetProperty()
{
    return impl::call_factory<SwipeBackThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics>([&](auto&& f) { return f.FromVerticalOffsetProperty(); });
}

inline SwipeHintThemeAnimation::SwipeHintThemeAnimation() :
    SwipeHintThemeAnimation(impl::call_factory<SwipeHintThemeAnimation>([](auto&& f) { return f.template ActivateInstance<SwipeHintThemeAnimation>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty SwipeHintThemeAnimation::TargetNameProperty()
{
    return impl::call_factory<SwipeHintThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics>([&](auto&& f) { return f.TargetNameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SwipeHintThemeAnimation::ToHorizontalOffsetProperty()
{
    return impl::call_factory<SwipeHintThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics>([&](auto&& f) { return f.ToHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SwipeHintThemeAnimation::ToVerticalOffsetProperty()
{
    return impl::call_factory<SwipeHintThemeAnimation, Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics>([&](auto&& f) { return f.ToVerticalOffsetProperty(); });
}

inline bool Timeline::AllowDependentAnimations()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.AllowDependentAnimations(); });
}

inline void Timeline::AllowDependentAnimations(bool value)
{
    impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.AllowDependentAnimations(value); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::AutoReverseProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.AutoReverseProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::BeginTimeProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.BeginTimeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::DurationProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.DurationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::SpeedRatioProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.SpeedRatioProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::FillBehaviorProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.FillBehaviorProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty Timeline::RepeatBehaviorProperty()
{
    return impl::call_factory<Timeline, Windows::UI::Xaml::Media::Animation::ITimelineStatics>([&](auto&& f) { return f.RepeatBehaviorProperty(); });
}

inline TimelineCollection::TimelineCollection() :
    TimelineCollection(impl::call_factory<TimelineCollection>([](auto&& f) { return f.template ActivateInstance<TimelineCollection>(); }))
{}

inline TransitionCollection::TransitionCollection() :
    TransitionCollection(impl::call_factory<TransitionCollection>([](auto&& f) { return f.template ActivateInstance<TransitionCollection>(); }))
{}

template <typename D> hstring INavigationTransitionInfoOverridesT<D>::GetNavigationStateCore() const
{
    return shim().template try_as<INavigationTransitionInfoOverrides>().GetNavigationStateCore();
}

template <typename D> void INavigationTransitionInfoOverridesT<D>::SetNavigationStateCore(param::hstring const& navigationState) const
{
    return shim().template try_as<INavigationTransitionInfoOverrides>().SetNavigationStateCore(navigationState);
}

template <typename D, typename... Interfaces>
struct BasicConnectedAnimationConfigurationT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
{
    using composable = BasicConnectedAnimationConfiguration;

protected:
    BasicConnectedAnimationConfigurationT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorKeyFrameT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IColorKeyFrame, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::ColorKeyFrame, Windows::UI::Xaml::DependencyObject>
{
    using composable = ColorKeyFrame;

protected:
    ColorKeyFrameT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::ColorKeyFrame, Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DirectConnectedAnimationConfigurationT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
{
    using composable = DirectConnectedAnimationConfiguration;

protected:
    DirectConnectedAnimationConfigurationT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DoubleKeyFrameT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::DoubleKeyFrame, Windows::UI::Xaml::DependencyObject>
{
    using composable = DoubleKeyFrame;

protected:
    DoubleKeyFrameT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::DoubleKeyFrame, Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GravityConnectedAnimationConfigurationT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration>
{
    using composable = GravityConnectedAnimationConfiguration;

protected:
    GravityConnectedAnimationConfigurationT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration, Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct NavigationTransitionInfoT :
    implements<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverridesT<D>
{
    using composable = NavigationTransitionInfo;

protected:
    NavigationTransitionInfoT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo, Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ObjectKeyFrameT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IObjectKeyFrame, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::ObjectKeyFrame, Windows::UI::Xaml::DependencyObject>
{
    using composable = ObjectKeyFrame;

protected:
    ObjectKeyFrameT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::ObjectKeyFrame, Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PointKeyFrameT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::IPointKeyFrame, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::PointKeyFrame, Windows::UI::Xaml::DependencyObject>
{
    using composable = PointKeyFrame;

protected:
    PointKeyFrameT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::PointKeyFrame, Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TimelineT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Animation::ITimeline, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Media::Animation::Timeline, Windows::UI::Xaml::DependencyObject>
{
    using composable = Timeline;

protected:
    TimelineT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Animation::Timeline, Windows::UI::Xaml::Media::Animation::ITimelineFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IAddDeleteThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBackEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBackEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBackEaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBasicConnectedAnimationConfigurationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBeginStoryboardStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBounceEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBounceEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IBounceEaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICircleEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ICircleEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorAnimationUsingKeyFramesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IColorKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ICommonNavigationTransitionInfoStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimation3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationConfigurationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationService> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IConnectedAnimationServiceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IContentThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IContinuumNavigationTransitionInfoStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ICubicEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ICubicEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDirectConnectedAnimationConfigurationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDiscreteObjectKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDiscretePointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleAnimationUsingKeyFramesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDoubleKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDragItemThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDragOverThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDrillInNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDrillInThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDrillOutThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IDropTargetItemThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingColorKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingDoubleKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingFunctionBaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEasingPointKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEdgeUIThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IElasticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IElasticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IElasticEaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEntranceNavigationTransitionInfoStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IEntranceThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IExponentialEaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IFadeInThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IFadeOutThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfiguration2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IGravityConnectedAnimationConfigurationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeySpline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IKeySpline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IKeyTimeHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ILinearColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ILinearDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ILinearPointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::INavigationThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::INavigationTransitionInfoOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IObjectAnimationUsingKeyFramesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IObjectKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPaneThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointAnimationUsingKeyFramesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointerDownThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPointerUpThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopInThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopOutThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPopupThemeTransitionStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPowerEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPowerEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IPowerEaseStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuadraticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IQuadraticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuarticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IQuarticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IQuinticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IQuinticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IReorderThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IReorderThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepeatBehaviorHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransition2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IRepositionThemeTransitionStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISineEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISineEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfo2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISlideNavigationTransitionInfoStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplineColorKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplineDoubleKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplinePointKeyFrameStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplitCloseThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISplitOpenThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IStoryboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IStoryboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::IStoryboardStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISuppressNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISwipeBackThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ISwipeHintThemeAnimationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimeline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ITimeline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ITimelineFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ITimelineStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ITransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ITransitionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ITransitionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::AddDeleteThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::AddDeleteThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BackEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::BackEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::BasicConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BeginStoryboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::BeginStoryboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::BounceEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::BounceEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CircleEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::CircleEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ColorAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ColorKeyFrameCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CommonNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::CommonNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ConnectedAnimationService> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ContentThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ContentThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ContinuumNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ContinuumNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::CubicEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::CubicEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DirectConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DiscreteColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DiscreteDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscreteObjectKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DiscreteObjectKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DiscretePointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DiscretePointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DoubleAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DoubleKeyFrameCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DragItemThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DragItemThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DragOverThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DragOverThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillInNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DrillInNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DrillInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DrillOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DrillOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::DropTargetItemThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::DropTargetItemThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EasingColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EasingDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EasingFunctionBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EasingPointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EasingPointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EdgeUIThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EdgeUIThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ElasticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ElasticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EntranceNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EntranceNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::EntranceThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::EntranceThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ExponentialEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ExponentialEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::FadeInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::FadeInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::FadeOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::FadeOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::GravityConnectedAnimationConfiguration> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::KeySpline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::KeySpline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::KeyTimeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::KeyTimeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::LinearColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::LinearDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::LinearPointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::LinearPointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::NavigationThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::NavigationThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::NavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ObjectAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ObjectKeyFrameCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PaneThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PaneThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointAnimationUsingKeyFrames> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointAnimationUsingKeyFrames> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointKeyFrameCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointerDownThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointerDownThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PointerUpThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PointerUpThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopInThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PopInThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopOutThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PopOutThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PopupThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PopupThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::PowerEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::PowerEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuadraticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::QuadraticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuarticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::QuarticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::QuinticEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::QuinticEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::ReorderThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::ReorderThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehaviorHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::RepeatBehaviorHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::RepositionThemeTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SineEase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SineEase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SlideNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplineColorKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SplineColorKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplineDoubleKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SplineDoubleKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplinePointKeyFrame> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SplinePointKeyFrame> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplitCloseThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SplitCloseThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SplitOpenThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SplitOpenThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Storyboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::Storyboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SuppressNavigationTransitionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SuppressNavigationTransitionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SwipeBackThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SwipeBackThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::SwipeHintThemeAnimation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::SwipeHintThemeAnimation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Timeline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::Timeline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::TimelineCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::Transition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::Transition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Animation::TransitionCollection> {};

}
