// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/impl/Windows.Devices.Input.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ICrossSlidingEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ICrossSlidingEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::CrossSlidingState consume_Windows_UI_Input_ICrossSlidingEventArgs<D>::CrossSlidingState() const
{
    Windows::UI::Input::CrossSlidingState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ICrossSlidingEventArgs)->get_CrossSlidingState(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IDraggingEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IDraggingEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IDraggingEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IDraggingEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::DraggingState consume_Windows_UI_Input_IDraggingEventArgs<D>::DraggingState() const
{
    Windows::UI::Input::DraggingState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IDraggingEventArgs)->get_DraggingState(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IEdgeGesture<D>::Starting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->add_Starting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Starting_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Starting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Starting_revoker>(this, Starting(handler));
}

template <typename D> void consume_Windows_UI_Input_IEdgeGesture<D>::Starting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->remove_Starting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IEdgeGesture<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Completed_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_UI_Input_IEdgeGesture<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->remove_Completed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->add_Canceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IEdgeGesture<D>::Canceled_revoker consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Canceled_revoker>(this, Canceled(handler));
}

template <typename D> void consume_Windows_UI_Input_IEdgeGesture<D>::Canceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IEdgeGesture)->remove_Canceled(get_abi(token)));
}

template <typename D> Windows::UI::Input::EdgeGestureKind consume_Windows_UI_Input_IEdgeGestureEventArgs<D>::Kind() const
{
    Windows::UI::Input::EdgeGestureKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IEdgeGestureEventArgs)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::EdgeGesture consume_Windows_UI_Input_IEdgeGestureStatics<D>::GetForCurrentView() const
{
    Windows::UI::Input::EdgeGesture current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IEdgeGestureStatics)->GetForCurrentView(put_abi(current)));
    return current;
}

template <typename D> Windows::UI::Input::GestureSettings consume_Windows_UI_Input_IGestureRecognizer<D>::GestureSettings() const
{
    Windows::UI::Input::GestureSettings value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_GestureSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::GestureSettings(Windows::UI::Input::GestureSettings const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_GestureSettings(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::IsInertial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_IsInertial(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_IsActive(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::ShowGestureFeedback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_ShowGestureFeedback(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ShowGestureFeedback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_ShowGestureFeedback(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IGestureRecognizer<D>::PivotCenter() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_PivotCenter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::PivotCenter(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_PivotCenter(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::PivotRadius() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_PivotRadius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::PivotRadius(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_PivotRadius(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDeceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaTranslationDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDeceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaTranslationDeceleration(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationDeceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaRotationDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationDeceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaRotationDeceleration(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansionDeceleration() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaExpansionDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansionDeceleration(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaExpansionDeceleration(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDisplacement() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaTranslationDisplacement(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaTranslationDisplacement(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaTranslationDisplacement(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaRotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaRotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaRotationAngle(value));
}

template <typename D> float consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansion() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_InertiaExpansion(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::InertiaExpansion(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_InertiaExpansion(value));
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationExact() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_ManipulationExact(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationExact(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_ManipulationExact(value));
}

template <typename D> Windows::UI::Input::CrossSlideThresholds consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideThresholds() const
{
    Windows::UI::Input::CrossSlideThresholds value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_CrossSlideThresholds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideThresholds(Windows::UI::Input::CrossSlideThresholds const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_CrossSlideThresholds(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideHorizontally() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_CrossSlideHorizontally(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideHorizontally(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_CrossSlideHorizontally(value));
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideExact() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_CrossSlideExact(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSlideExact(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_CrossSlideExact(value));
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::AutoProcessInertia() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_AutoProcessInertia(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::AutoProcessInertia(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->put_AutoProcessInertia(value));
}

template <typename D> Windows::UI::Input::MouseWheelParameters consume_Windows_UI_Input_IGestureRecognizer<D>::MouseWheelParameters() const
{
    Windows::UI::Input::MouseWheelParameters value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->get_MouseWheelParameters(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IGestureRecognizer<D>::CanBeDoubleTap(Windows::UI::Input::PointerPoint const& value) const
{
    bool canBeDoubleTap{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->CanBeDoubleTap(get_abi(value), &canBeDoubleTap));
    return canBeDoubleTap;
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessDownEvent(Windows::UI::Input::PointerPoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->ProcessDownEvent(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessMoveEvents(param::vector<Windows::UI::Input::PointerPoint> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->ProcessMoveEvents(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessUpEvent(Windows::UI::Input::PointerPoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->ProcessUpEvent(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessMouseWheelEvent(Windows::UI::Input::PointerPoint const& value, bool isShiftKeyDown, bool isControlKeyDown) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->ProcessMouseWheelEvent(get_abi(value), isShiftKeyDown, isControlKeyDown));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ProcessInertia() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->ProcessInertia());
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::CompleteGesture() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->CompleteGesture());
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::TappedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_Tapped(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::TappedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::Tapped(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_Tapped(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::RightTappedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_RightTapped(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::RightTappedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RightTapped_revoker>(this, RightTapped(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::RightTapped(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_RightTapped(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::HoldingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_Holding(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Holding_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::HoldingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Holding_revoker>(this, Holding(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::Holding(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_Holding(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::DraggingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_Dragging(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::DraggingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Dragging_revoker>(this, Dragging(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::Dragging(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_Dragging(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_ManipulationStarted(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationStarted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_ManipulationStarted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_ManipulationUpdated(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationUpdated_revoker>(this, ManipulationUpdated(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationUpdated(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_ManipulationUpdated(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_ManipulationInertiaStarting(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationInertiaStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationInertiaStarting_revoker>(this, ManipulationInertiaStarting(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationInertiaStarting(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_ManipulationInertiaStarting(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_ManipulationCompleted(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::ManipulationCompleted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_ManipulationCompleted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::CrossSlidingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->add_CrossSliding(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding_revoker consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::CrossSlidingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CrossSliding_revoker>(this, CrossSliding(handler));
}

template <typename D> void consume_Windows_UI_Input_IGestureRecognizer<D>::CrossSliding(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IGestureRecognizer)->remove_CrossSliding(get_abi(cookie)));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IHoldingEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IHoldingEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IHoldingEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IHoldingEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::HoldingState consume_Windows_UI_Input_IHoldingEventArgs<D>::HoldingState() const
{
    Windows::UI::Input::HoldingState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IHoldingEventArgs)->get_HoldingState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::InputActivationState consume_Windows_UI_Input_IInputActivationListener<D>::State() const
{
    Windows::UI::Input::InputActivationState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IInputActivationListener)->get_State(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Input::InputActivationListener, Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IInputActivationListener)->add_InputActivationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged_revoker consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::InputActivationListener, Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InputActivationChanged_revoker>(this, InputActivationChanged(handler));
}

template <typename D> void consume_Windows_UI_Input_IInputActivationListener<D>::InputActivationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IInputActivationListener)->remove_InputActivationChanged(get_abi(token)));
}

template <typename D> Windows::UI::Input::InputActivationState consume_Windows_UI_Input_IInputActivationListenerActivationChangedEventArgs<D>::State() const
{
    Windows::UI::Input::InputActivationState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::IsInterceptionEnabledWhenInForeground() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->get_IsInterceptionEnabledWhenInForeground(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::IsInterceptionEnabledWhenInForeground(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->put_IsInterceptionEnabledWhenInForeground(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->add_KeyDown(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown_revoker consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
}

template <typename D> void consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyDown(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->remove_KeyDown(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->add_KeyUp(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp_revoker consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
}

template <typename D> void consume_Windows_UI_Input_IKeyboardDeliveryInterceptor<D>::KeyUp(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptor)->remove_KeyUp(get_abi(token)));
}

template <typename D> Windows::UI::Input::KeyboardDeliveryInterceptor consume_Windows_UI_Input_IKeyboardDeliveryInterceptorStatics<D>::GetForCurrentView() const
{
    Windows::UI::Input::KeyboardDeliveryInterceptor keyboardDeliverySettings{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IKeyboardDeliveryInterceptorStatics)->GetForCurrentView(put_abi(keyboardDeliverySettings)));
    return keyboardDeliverySettings;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationCompletedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationCompletedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationCompletedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Input_IManipulationCompletedEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationCompletedEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Delta() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Delta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Input_IManipulationInertiaStartingEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationInertiaStartingEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationStartedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationStartedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationStartedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationStartedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationUpdatedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Delta() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Delta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Input_IManipulationUpdatedEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IManipulationUpdatedEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IMouseWheelParameters<D>::CharTranslation() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->get_CharTranslation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IMouseWheelParameters<D>::CharTranslation(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->put_CharTranslation(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaScale() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->get_DeltaScale(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaScale(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->put_DeltaScale(value));
}

template <typename D> float consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaRotationAngle() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->get_DeltaRotationAngle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IMouseWheelParameters<D>::DeltaRotationAngle(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->put_DeltaRotationAngle(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IMouseWheelParameters<D>::PageTranslation() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->get_PageTranslation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IMouseWheelParameters<D>::PageTranslation(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IMouseWheelParameters)->put_PageTranslation(get_abi(value)));
}

template <typename D> Windows::Devices::Input::PointerDevice consume_Windows_UI_Input_IPointerPoint<D>::PointerDevice() const
{
    Windows::Devices::Input::PointerDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_PointerDevice(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IPointerPoint<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IPointerPoint<D>::RawPosition() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_RawPosition(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_IPointerPoint<D>::PointerId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_PointerId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_IPointerPoint<D>::FrameId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_FrameId(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_UI_Input_IPointerPoint<D>::Timestamp() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_Timestamp(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPoint<D>::IsInContact() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_IsInContact(&value));
    return value;
}

template <typename D> Windows::UI::Input::PointerPointProperties consume_Windows_UI_Input_IPointerPoint<D>::Properties() const
{
    Windows::UI::Input::PointerPointProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPoint)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Input_IPointerPointProperties<D>::Pressure() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_Pressure(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsInverted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsInverted(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsEraser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsEraser(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_IPointerPointProperties<D>::Orientation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_Orientation(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_IPointerPointProperties<D>::XTilt() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_XTilt(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_IPointerPointProperties<D>::YTilt() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_YTilt(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Input_IPointerPointProperties<D>::Twist() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_Twist(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_IPointerPointProperties<D>::ContactRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_ContactRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_IPointerPointProperties<D>::ContactRectRaw() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_ContactRectRaw(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::TouchConfidence() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_TouchConfidence(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsLeftButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsLeftButtonPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsRightButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsRightButtonPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsMiddleButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsMiddleButtonPressed(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Input_IPointerPointProperties<D>::MouseWheelDelta() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_MouseWheelDelta(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsHorizontalMouseWheel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsHorizontalMouseWheel(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsPrimary() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsPrimary(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsInRange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsInRange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsCanceled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsCanceled(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsBarrelButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsBarrelButtonPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsXButton1Pressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsXButton1Pressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::IsXButton2Pressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_IsXButton2Pressed(&value));
    return value;
}

template <typename D> Windows::UI::Input::PointerUpdateKind consume_Windows_UI_Input_IPointerPointProperties<D>::PointerUpdateKind() const
{
    Windows::UI::Input::PointerUpdateKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->get_PointerUpdateKind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointProperties<D>::HasUsage(uint32_t usagePage, uint32_t usageId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->HasUsage(usagePage, usageId, &value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Input_IPointerPointProperties<D>::GetUsageValue(uint32_t usagePage, uint32_t usageId) const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties)->GetUsageValue(usagePage, usageId, &value));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_UI_Input_IPointerPointProperties2<D>::ZDistance() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointProperties2)->get_ZDistance(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::PointerPoint consume_Windows_UI_Input_IPointerPointStatics<D>::GetCurrentPoint(uint32_t pointerId) const
{
    Windows::UI::Input::PointerPoint pointerPoint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointStatics)->GetCurrentPoint(pointerId, put_abi(pointerPoint)));
    return pointerPoint;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> consume_Windows_UI_Input_IPointerPointStatics<D>::GetIntermediatePoints(uint32_t pointerId) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> pointerPoints{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointStatics)->GetIntermediatePoints(pointerId, put_abi(pointerPoints)));
    return pointerPoints;
}

template <typename D> Windows::UI::Input::PointerPoint consume_Windows_UI_Input_IPointerPointStatics<D>::GetCurrentPoint(uint32_t pointerId, Windows::UI::Input::IPointerPointTransform const& transform) const
{
    Windows::UI::Input::PointerPoint pointerPoint{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointStatics)->GetCurrentPointTransformed(pointerId, get_abi(transform), put_abi(pointerPoint)));
    return pointerPoint;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> consume_Windows_UI_Input_IPointerPointStatics<D>::GetIntermediatePoints(uint32_t pointerId, Windows::UI::Input::IPointerPointTransform const& transform) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> pointerPoints{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointStatics)->GetIntermediatePointsTransformed(pointerId, get_abi(transform), put_abi(pointerPoints)));
    return pointerPoints;
}

template <typename D> Windows::UI::Input::IPointerPointTransform consume_Windows_UI_Input_IPointerPointTransform<D>::Inverse() const
{
    Windows::UI::Input::IPointerPointTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointTransform)->get_Inverse(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IPointerPointTransform<D>::TryTransform(Windows::Foundation::Point const& inPoint, Windows::Foundation::Point& outPoint) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointTransform)->TryTransform(get_abi(inPoint), put_abi(outPoint), &returnValue));
    return returnValue;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_IPointerPointTransform<D>::TransformBounds(Windows::Foundation::Rect const& rect) const
{
    Windows::Foundation::Rect returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerPointTransform)->TransformBounds(get_abi(rect), put_abi(returnValue)));
    return returnValue;
}

template <typename D> void consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsContactFeedbackEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerVisualizationSettings)->put_IsContactFeedbackEnabled(value));
}

template <typename D> bool consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsContactFeedbackEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerVisualizationSettings)->get_IsContactFeedbackEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsBarrelButtonFeedbackEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerVisualizationSettings)->put_IsBarrelButtonFeedbackEnabled(value));
}

template <typename D> bool consume_Windows_UI_Input_IPointerVisualizationSettings<D>::IsBarrelButtonFeedbackEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerVisualizationSettings)->get_IsBarrelButtonFeedbackEnabled(&value));
    return value;
}

template <typename D> Windows::UI::Input::PointerVisualizationSettings consume_Windows_UI_Input_IPointerVisualizationSettingsStatics<D>::GetForCurrentView() const
{
    Windows::UI::Input::PointerVisualizationSettings visualizationSettings{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IPointerVisualizationSettingsStatics)->GetForCurrentView(put_abi(visualizationSettings)));
    return visualizationSettings;
}

template <typename D> Windows::UI::Input::RadialControllerMenu consume_Windows_UI_Input_IRadialController<D>::Menu() const
{
    Windows::UI::Input::RadialControllerMenu value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->get_Menu(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Input_IRadialController<D>::RotationResolutionInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->get_RotationResolutionInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::RotationResolutionInDegrees(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->put_RotationResolutionInDegrees(value));
}

template <typename D> bool consume_Windows_UI_Input_IRadialController<D>::UseAutomaticHapticFeedback() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->get_UseAutomaticHapticFeedback(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::UseAutomaticHapticFeedback(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->put_UseAutomaticHapticFeedback(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ScreenContactStarted(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ScreenContactStarted_revoker>(this, ScreenContactStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ScreenContactStarted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ScreenContactStarted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ScreenContactEnded(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ScreenContactEnded_revoker>(this, ScreenContactEnded(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ScreenContactEnded(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ScreenContactEnded(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ScreenContactContinued(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued_revoker consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ScreenContactContinued_revoker>(this, ScreenContactContinued(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ScreenContactContinued(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ScreenContactContinued(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ControlLost(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ControlLost(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ControlLost_revoker consume_Windows_UI_Input_IRadialController<D>::ControlLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ControlLost_revoker>(this, ControlLost(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ControlLost(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ControlLost(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::RotationChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_RotationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::RotationChanged_revoker consume_Windows_UI_Input_IRadialController<D>::RotationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerRotationChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RotationChanged_revoker>(this, RotationChanged(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::RotationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_RotationChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ButtonClicked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ButtonClicked_revoker consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonClickedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ButtonClicked_revoker>(this, ButtonClicked(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ButtonClicked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ButtonClicked(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController)->add_ControlAcquired(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController<D>::ControlAcquired_revoker consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ControlAcquired_revoker>(this, ControlAcquired(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController<D>::ControlAcquired(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController)->remove_ControlAcquired(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController2)->add_ButtonPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonPressedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ButtonPressed_revoker>(this, ButtonPressed(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController2<D>::ButtonPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController2)->remove_ButtonPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController2)->add_ButtonHolding(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ButtonHolding_revoker>(this, ButtonHolding(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController2<D>::ButtonHolding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController2)->remove_ButtonHolding(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialController2)->add_ButtonReleased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased_revoker consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ButtonReleased_revoker>(this, ButtonReleased(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialController2<D>::ButtonReleased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialController2)->remove_ButtonReleased(get_abi(token)));
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonClickedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerButtonClickedEventArgs2<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonClickedEventArgs2)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonHoldingEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerButtonHoldingEventArgs<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonHoldingEventArgs)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonPressedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerButtonPressedEventArgs<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonPressedEventArgs)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonReleasedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerButtonReleasedEventArgs<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerButtonReleasedEventArgs)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfiguration<D>::SetDefaultMenuItems(param::iterable<Windows::UI::Input::RadialControllerSystemMenuItemKind> const& buttons) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration)->SetDefaultMenuItems(get_abi(buttons)));
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfiguration<D>::ResetToDefaultMenuItems() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration)->ResetToDefaultMenuItems());
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerConfiguration<D>::TrySelectDefaultMenuItem(Windows::UI::Input::RadialControllerSystemMenuItemKind const& type) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration)->TrySelectDefaultMenuItem(get_abi(type), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::ActiveControllerWhenMenuIsSuppressed(Windows::UI::Input::RadialController const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration2)->put_ActiveControllerWhenMenuIsSuppressed(get_abi(value)));
}

template <typename D> Windows::UI::Input::RadialController consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::ActiveControllerWhenMenuIsSuppressed() const
{
    Windows::UI::Input::RadialController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration2)->get_ActiveControllerWhenMenuIsSuppressed(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::IsMenuSuppressed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration2)->put_IsMenuSuppressed(value));
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerConfiguration2<D>::IsMenuSuppressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfiguration2)->get_IsMenuSuppressed(&value));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerConfiguration consume_Windows_UI_Input_IRadialControllerConfigurationStatics<D>::GetForCurrentView() const
{
    Windows::UI::Input::RadialControllerConfiguration configuration{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfigurationStatics)->GetForCurrentView(put_abi(configuration)));
    return configuration;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::AppController(Windows::UI::Input::RadialController const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfigurationStatics2)->put_AppController(get_abi(value)));
}

template <typename D> Windows::UI::Input::RadialController consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::AppController() const
{
    Windows::UI::Input::RadialController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfigurationStatics2)->get_AppController(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::IsAppControllerEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfigurationStatics2)->put_IsAppControllerEnabled(value));
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerConfigurationStatics2<D>::IsAppControllerEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerConfigurationStatics2)->get_IsAppControllerEnabled(&value));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerControlAcquiredEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2<D>::IsButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2)->get_IsButtonPressed(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerControlAcquiredEventArgs2<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::RadialControllerMenuItem> consume_Windows_UI_Input_IRadialControllerMenu<D>::Items() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::RadialControllerMenuItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->get_Items(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerMenu<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerMenu<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->put_IsEnabled(value));
}

template <typename D> Windows::UI::Input::RadialControllerMenuItem consume_Windows_UI_Input_IRadialControllerMenu<D>::GetSelectedMenuItem() const
{
    Windows::UI::Input::RadialControllerMenuItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->GetSelectedMenuItem(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerMenu<D>::SelectMenuItem(Windows::UI::Input::RadialControllerMenuItem const& menuItem) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->SelectMenuItem(get_abi(menuItem)));
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerMenu<D>::TrySelectPreviouslySelectedMenuItem() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenu)->TrySelectPreviouslySelectedMenuItem(&result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Input_IRadialControllerMenuItem<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItem)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Tag() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItem)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Tag(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItem)->put_Tag(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialControllerMenuItem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItem)->add_Invoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked_revoker consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialControllerMenuItem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
}

template <typename D> void consume_Windows_UI_Input_IRadialControllerMenuItem<D>::Invoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItem)->remove_Invoked(get_abi(token)));
}

template <typename D> Windows::UI::Input::RadialControllerMenuItem consume_Windows_UI_Input_IRadialControllerMenuItemStatics<D>::CreateFromIcon(param::hstring const& displayText, Windows::Storage::Streams::RandomAccessStreamReference const& icon) const
{
    Windows::UI::Input::RadialControllerMenuItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItemStatics)->CreateFromIcon(get_abi(displayText), get_abi(icon), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::RadialControllerMenuItem consume_Windows_UI_Input_IRadialControllerMenuItemStatics<D>::CreateFromKnownIcon(param::hstring const& displayText, Windows::UI::Input::RadialControllerMenuKnownIcon const& value) const
{
    Windows::UI::Input::RadialControllerMenuItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItemStatics)->CreateFromKnownIcon(get_abi(displayText), get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::RadialControllerMenuItem consume_Windows_UI_Input_IRadialControllerMenuItemStatics2<D>::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily) const
{
    Windows::UI::Input::RadialControllerMenuItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItemStatics2)->CreateFromFontGlyph(get_abi(displayText), get_abi(glyph), get_abi(fontFamily), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::RadialControllerMenuItem consume_Windows_UI_Input_IRadialControllerMenuItemStatics2<D>::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, Windows::Foundation::Uri const& fontUri) const
{
    Windows::UI::Input::RadialControllerMenuItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerMenuItemStatics2)->CreateFromFontGlyphWithUri(get_abi(displayText), get_abi(glyph), get_abi(fontFamily), get_abi(fontUri), put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs<D>::RotationDeltaInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerRotationChangedEventArgs)->get_RotationDeltaInDegrees(&value));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerRotationChangedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2<D>::IsButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerRotationChangedEventArgs2)->get_IsButtonPressed(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerRotationChangedEventArgs2<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerRotationChangedEventArgs2)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_IRadialControllerScreenContact<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContact)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IRadialControllerScreenContact<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContact)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2<D>::IsButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2)->get_IsButtonPressed(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerScreenContactContinuedEventArgs2<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs<D>::IsButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs)->get_IsButtonPressed(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerScreenContactEndedEventArgs<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::RadialControllerScreenContact consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs<D>::Contact() const
{
    Windows::UI::Input::RadialControllerScreenContact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2<D>::IsButtonPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2)->get_IsButtonPressed(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_IRadialControllerScreenContactStartedEventArgs2<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_IRadialControllerStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerStatics)->IsSupported(&result));
    return result;
}

template <typename D> Windows::UI::Input::RadialController consume_Windows_UI_Input_IRadialControllerStatics<D>::CreateForCurrentView() const
{
    Windows::UI::Input::RadialController result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRadialControllerStatics)->CreateForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_IRightTappedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRightTappedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_IRightTappedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::IRightTappedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Input_ITappedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ITappedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_ITappedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ITappedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_ITappedEventArgs<D>::TapCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::ITappedEventArgs)->get_TapCount(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Input::IAttachableInputObject> : produce_base<D, Windows::UI::Input::IAttachableInputObject>
{};

template <typename D>
struct produce<D, Windows::UI::Input::IAttachableInputObjectFactory> : produce_base<D, Windows::UI::Input::IAttachableInputObjectFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Input::ICrossSlidingEventArgs> : produce_base<D, Windows::UI::Input::ICrossSlidingEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CrossSlidingState(Windows::UI::Input::CrossSlidingState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlidingState, WINRT_WRAP(Windows::UI::Input::CrossSlidingState));
            *value = detach_from<Windows::UI::Input::CrossSlidingState>(this->shim().CrossSlidingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IDraggingEventArgs> : produce_base<D, Windows::UI::Input::IDraggingEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DraggingState(Windows::UI::Input::DraggingState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DraggingState, WINRT_WRAP(Windows::UI::Input::DraggingState));
            *value = detach_from<Windows::UI::Input::DraggingState>(this->shim().DraggingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IEdgeGesture> : produce_base<D, Windows::UI::Input::IEdgeGesture>
{
    int32_t WINRT_CALL add_Starting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Starting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Starting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Starting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Starting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Starting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_Canceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Canceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::EdgeGesture, Windows::UI::Input::EdgeGestureEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Canceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Canceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IEdgeGestureEventArgs> : produce_base<D, Windows::UI::Input::IEdgeGestureEventArgs>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::Input::EdgeGestureKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Input::EdgeGestureKind));
            *value = detach_from<Windows::UI::Input::EdgeGestureKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IEdgeGestureStatics> : produce_base<D, Windows::UI::Input::IEdgeGestureStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Input::EdgeGesture));
            *current = detach_from<Windows::UI::Input::EdgeGesture>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IGestureRecognizer> : produce_base<D, Windows::UI::Input::IGestureRecognizer>
{
    int32_t WINRT_CALL get_GestureSettings(Windows::UI::Input::GestureSettings* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GestureSettings, WINRT_WRAP(Windows::UI::Input::GestureSettings));
            *value = detach_from<Windows::UI::Input::GestureSettings>(this->shim().GestureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GestureSettings(Windows::UI::Input::GestureSettings value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GestureSettings, WINRT_WRAP(void), Windows::UI::Input::GestureSettings const&);
            this->shim().GestureSettings(*reinterpret_cast<Windows::UI::Input::GestureSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInertial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInertial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInertial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ShowGestureFeedback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowGestureFeedback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowGestureFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowGestureFeedback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowGestureFeedback, WINRT_WRAP(void), bool);
            this->shim().ShowGestureFeedback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PivotCenter(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PivotCenter, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().PivotCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PivotCenter(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PivotCenter, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().PivotCenter(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PivotRadius(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PivotRadius, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PivotRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PivotRadius(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PivotRadius, WINRT_WRAP(void), float);
            this->shim().PivotRadius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaTranslationDeceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaTranslationDeceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaTranslationDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaTranslationDeceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaTranslationDeceleration, WINRT_WRAP(void), float);
            this->shim().InertiaTranslationDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaRotationDeceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaRotationDeceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaRotationDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaRotationDeceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaRotationDeceleration, WINRT_WRAP(void), float);
            this->shim().InertiaRotationDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaExpansionDeceleration(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaExpansionDeceleration, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaExpansionDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaExpansionDeceleration(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaExpansionDeceleration, WINRT_WRAP(void), float);
            this->shim().InertiaExpansionDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaTranslationDisplacement(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaTranslationDisplacement, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaTranslationDisplacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaTranslationDisplacement(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaTranslationDisplacement, WINRT_WRAP(void), float);
            this->shim().InertiaTranslationDisplacement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaRotationAngle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaRotationAngle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaRotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaRotationAngle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaRotationAngle, WINRT_WRAP(void), float);
            this->shim().InertiaRotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InertiaExpansion(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaExpansion, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().InertiaExpansion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InertiaExpansion(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InertiaExpansion, WINRT_WRAP(void), float);
            this->shim().InertiaExpansion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationExact(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationExact, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ManipulationExact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ManipulationExact(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationExact, WINRT_WRAP(void), bool);
            this->shim().ManipulationExact(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideThresholds, WINRT_WRAP(Windows::UI::Input::CrossSlideThresholds));
            *value = detach_from<Windows::UI::Input::CrossSlideThresholds>(this->shim().CrossSlideThresholds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CrossSlideThresholds(struct struct_Windows_UI_Input_CrossSlideThresholds value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideThresholds, WINRT_WRAP(void), Windows::UI::Input::CrossSlideThresholds const&);
            this->shim().CrossSlideThresholds(*reinterpret_cast<Windows::UI::Input::CrossSlideThresholds const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CrossSlideHorizontally(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideHorizontally, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CrossSlideHorizontally());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CrossSlideHorizontally(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideHorizontally, WINRT_WRAP(void), bool);
            this->shim().CrossSlideHorizontally(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CrossSlideExact(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideExact, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CrossSlideExact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CrossSlideExact(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSlideExact, WINRT_WRAP(void), bool);
            this->shim().CrossSlideExact(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoProcessInertia(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoProcessInertia, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoProcessInertia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoProcessInertia(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoProcessInertia, WINRT_WRAP(void), bool);
            this->shim().AutoProcessInertia(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MouseWheelParameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelParameters, WINRT_WRAP(Windows::UI::Input::MouseWheelParameters));
            *value = detach_from<Windows::UI::Input::MouseWheelParameters>(this->shim().MouseWheelParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanBeDoubleTap(void* value, bool* canBeDoubleTap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanBeDoubleTap, WINRT_WRAP(bool), Windows::UI::Input::PointerPoint const&);
            *canBeDoubleTap = detach_from<bool>(this->shim().CanBeDoubleTap(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessDownEvent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessDownEvent, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&);
            this->shim().ProcessDownEvent(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessMoveEvents(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessMoveEvents, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> const&);
            this->shim().ProcessMoveEvents(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessUpEvent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessUpEvent, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&);
            this->shim().ProcessUpEvent(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessMouseWheelEvent(void* value, bool isShiftKeyDown, bool isControlKeyDown) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessMouseWheelEvent, WINRT_WRAP(void), Windows::UI::Input::PointerPoint const&, bool, bool);
            this->shim().ProcessMouseWheelEvent(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&value), isShiftKeyDown, isControlKeyDown);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessInertia() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessInertia, WINRT_WRAP(void));
            this->shim().ProcessInertia();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompleteGesture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteGesture, WINRT_WRAP(void));
            this->shim().CompleteGesture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Tapped(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::TappedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::TappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Tapped(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_RightTapped(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::RightTappedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().RightTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::RightTappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RightTapped(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RightTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RightTapped(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_Holding(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Holding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::HoldingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().Holding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::HoldingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Holding(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Holding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Holding(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_Dragging(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dragging, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::DraggingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().Dragging(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::DraggingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Dragging(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Dragging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Dragging(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationStarted(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationStartedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationStarted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationUpdated(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationUpdatedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ManipulationUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationUpdated(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationUpdated(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationInertiaStarting(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationInertiaStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationInertiaStartingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ManipulationInertiaStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationInertiaStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationInertiaStarting(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationInertiaStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationCompleted(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationCompletedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::ManipulationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationCompleted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_CrossSliding(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CrossSliding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::CrossSlidingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().CrossSliding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::GestureRecognizer, Windows::UI::Input::CrossSlidingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CrossSliding(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CrossSliding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CrossSliding(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IHoldingEventArgs> : produce_base<D, Windows::UI::Input::IHoldingEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HoldingState(Windows::UI::Input::HoldingState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldingState, WINRT_WRAP(Windows::UI::Input::HoldingState));
            *value = detach_from<Windows::UI::Input::HoldingState>(this->shim().HoldingState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IInputActivationListener> : produce_base<D, Windows::UI::Input::IInputActivationListener>
{
    int32_t WINRT_CALL get_State(Windows::UI::Input::InputActivationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::UI::Input::InputActivationState));
            *value = detach_from<Windows::UI::Input::InputActivationState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_InputActivationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputActivationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::InputActivationListener, Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InputActivationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::InputActivationListener, Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InputActivationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InputActivationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InputActivationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> : produce_base<D, Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::UI::Input::InputActivationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::UI::Input::InputActivationState));
            *value = detach_from<Windows::UI::Input::InputActivationState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IKeyboardDeliveryInterceptor> : produce_base<D, Windows::UI::Input::IKeyboardDeliveryInterceptor>
{
    int32_t WINRT_CALL get_IsInterceptionEnabledWhenInForeground(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterceptionEnabledWhenInForeground, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInterceptionEnabledWhenInForeground());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInterceptionEnabledWhenInForeground(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterceptionEnabledWhenInForeground, WINRT_WRAP(void), bool);
            this->shim().IsInterceptionEnabledWhenInForeground(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_KeyDown(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyDown(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_KeyUp(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::KeyboardDeliveryInterceptor, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyUp(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> : produce_base<D, Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** keyboardDeliverySettings) noexcept final
    {
        try
        {
            *keyboardDeliverySettings = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Input::KeyboardDeliveryInterceptor));
            *keyboardDeliverySettings = detach_from<Windows::UI::Input::KeyboardDeliveryInterceptor>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IManipulationCompletedEventArgs> : produce_base<D, Windows::UI::Input::IManipulationCompletedEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cumulative, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocities, WINRT_WRAP(Windows::UI::Input::ManipulationVelocities));
            *value = detach_from<Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IManipulationInertiaStartingEventArgs> : produce_base<D, Windows::UI::Input::IManipulationInertiaStartingEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delta, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Delta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cumulative, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocities, WINRT_WRAP(Windows::UI::Input::ManipulationVelocities));
            *value = detach_from<Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IManipulationStartedEventArgs> : produce_base<D, Windows::UI::Input::IManipulationStartedEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cumulative, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IManipulationUpdatedEventArgs> : produce_base<D, Windows::UI::Input::IManipulationUpdatedEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delta, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Delta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cumulative, WINRT_WRAP(Windows::UI::Input::ManipulationDelta));
            *value = detach_from<Windows::UI::Input::ManipulationDelta>(this->shim().Cumulative());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocities, WINRT_WRAP(Windows::UI::Input::ManipulationVelocities));
            *value = detach_from<Windows::UI::Input::ManipulationVelocities>(this->shim().Velocities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IMouseWheelParameters> : produce_base<D, Windows::UI::Input::IMouseWheelParameters>
{
    int32_t WINRT_CALL get_CharTranslation(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharTranslation, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().CharTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharTranslation(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharTranslation, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().CharTranslation(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
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

    int32_t WINRT_CALL put_DeltaScale(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaScale, WINRT_WRAP(void), float);
            this->shim().DeltaScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeltaRotationAngle(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaRotationAngle, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DeltaRotationAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeltaRotationAngle(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeltaRotationAngle, WINRT_WRAP(void), float);
            this->shim().DeltaRotationAngle(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageTranslation(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageTranslation, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().PageTranslation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PageTranslation(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageTranslation, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().PageTranslation(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerPoint> : produce_base<D, Windows::UI::Input::IPointerPoint>
{
    int32_t WINRT_CALL get_PointerDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDevice, WINRT_WRAP(Windows::Devices::Input::PointerDevice));
            *value = detach_from<Windows::Devices::Input::PointerDevice>(this->shim().PointerDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawPosition(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawPosition, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().RawPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PointerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInContact(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInContact, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInContact());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::UI::Input::PointerPointProperties));
            *value = detach_from<Windows::UI::Input::PointerPointProperties>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerPointProperties> : produce_base<D, Windows::UI::Input::IPointerPointProperties>
{
    int32_t WINRT_CALL get_Pressure(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pressure, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Pressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInverted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInverted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInverted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEraser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEraser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEraser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XTilt(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XTilt, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().XTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YTilt(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YTilt, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().YTilt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Twist(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Twist, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Twist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ContactRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactRectRaw(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactRectRaw, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ContactRectRaw());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TouchConfidence(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchConfidence, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TouchConfidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLeftButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLeftButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLeftButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRightButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRightButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRightButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMiddleButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMiddleButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMiddleButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MouseWheelDelta(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseWheelDelta, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MouseWheelDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHorizontalMouseWheel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHorizontalMouseWheel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHorizontalMouseWheel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPrimary(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrimary, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrimary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInRange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInRange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCanceled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCanceled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCanceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBarrelButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBarrelButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBarrelButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsXButton1Pressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsXButton1Pressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsXButton1Pressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsXButton2Pressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsXButton2Pressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsXButton2Pressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerUpdateKind(Windows::UI::Input::PointerUpdateKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerUpdateKind, WINRT_WRAP(Windows::UI::Input::PointerUpdateKind));
            *value = detach_from<Windows::UI::Input::PointerUpdateKind>(this->shim().PointerUpdateKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HasUsage(uint32_t usagePage, uint32_t usageId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasUsage, WINRT_WRAP(bool), uint32_t, uint32_t);
            *value = detach_from<bool>(this->shim().HasUsage(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUsageValue(uint32_t usagePage, uint32_t usageId, int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUsageValue, WINRT_WRAP(int32_t), uint32_t, uint32_t);
            *value = detach_from<int32_t>(this->shim().GetUsageValue(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerPointProperties2> : produce_base<D, Windows::UI::Input::IPointerPointProperties2>
{
    int32_t WINRT_CALL get_ZDistance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZDistance, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().ZDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerPointStatics> : produce_base<D, Windows::UI::Input::IPointerPointStatics>
{
    int32_t WINRT_CALL GetCurrentPoint(uint32_t pointerId, void** pointerPoint) noexcept final
    {
        try
        {
            *pointerPoint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentPoint, WINRT_WRAP(Windows::UI::Input::PointerPoint), uint32_t);
            *pointerPoint = detach_from<Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIntermediatePoints(uint32_t pointerId, void** pointerPoints) noexcept final
    {
        try
        {
            *pointerPoints = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIntermediatePoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>), uint32_t);
            *pointerPoints = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentPointTransformed(uint32_t pointerId, void* transform, void** pointerPoint) noexcept final
    {
        try
        {
            *pointerPoint = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentPoint, WINRT_WRAP(Windows::UI::Input::PointerPoint), uint32_t, Windows::UI::Input::IPointerPointTransform const&);
            *pointerPoint = detach_from<Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(pointerId, *reinterpret_cast<Windows::UI::Input::IPointerPointTransform const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIntermediatePointsTransformed(uint32_t pointerId, void* transform, void** pointerPoints) noexcept final
    {
        try
        {
            *pointerPoints = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIntermediatePoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>), uint32_t, Windows::UI::Input::IPointerPointTransform const&);
            *pointerPoints = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(pointerId, *reinterpret_cast<Windows::UI::Input::IPointerPointTransform const*>(&transform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerPointTransform> : produce_base<D, Windows::UI::Input::IPointerPointTransform>
{
    int32_t WINRT_CALL get_Inverse(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Inverse, WINRT_WRAP(Windows::UI::Input::IPointerPointTransform));
            *value = detach_from<Windows::UI::Input::IPointerPointTransform>(this->shim().Inverse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTransform(Windows::Foundation::Point inPoint, Windows::Foundation::Point* outPoint, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTransform, WINRT_WRAP(bool), Windows::Foundation::Point const&, Windows::Foundation::Point&);
            *returnValue = detach_from<bool>(this->shim().TryTransform(*reinterpret_cast<Windows::Foundation::Point const*>(&inPoint), *reinterpret_cast<Windows::Foundation::Point*>(outPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransformBounds(Windows::Foundation::Rect rect, Windows::Foundation::Rect* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformBounds, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&);
            *returnValue = detach_from<Windows::Foundation::Rect>(this->shim().TransformBounds(*reinterpret_cast<Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerVisualizationSettings> : produce_base<D, Windows::UI::Input::IPointerVisualizationSettings>
{
    int32_t WINRT_CALL put_IsContactFeedbackEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContactFeedbackEnabled, WINRT_WRAP(void), bool);
            this->shim().IsContactFeedbackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsContactFeedbackEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContactFeedbackEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsContactFeedbackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsBarrelButtonFeedbackEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBarrelButtonFeedbackEnabled, WINRT_WRAP(void), bool);
            this->shim().IsBarrelButtonFeedbackEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBarrelButtonFeedbackEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBarrelButtonFeedbackEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBarrelButtonFeedbackEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IPointerVisualizationSettingsStatics> : produce_base<D, Windows::UI::Input::IPointerVisualizationSettingsStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** visualizationSettings) noexcept final
    {
        try
        {
            *visualizationSettings = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Input::PointerVisualizationSettings));
            *visualizationSettings = detach_from<Windows::UI::Input::PointerVisualizationSettings>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialController> : produce_base<D, Windows::UI::Input::IRadialController>
{
    int32_t WINRT_CALL get_Menu(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Menu, WINRT_WRAP(Windows::UI::Input::RadialControllerMenu));
            *value = detach_from<Windows::UI::Input::RadialControllerMenu>(this->shim().Menu());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationResolutionInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationResolutionInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationResolutionInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationResolutionInDegrees(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationResolutionInDegrees, WINRT_WRAP(void), double);
            this->shim().RotationResolutionInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UseAutomaticHapticFeedback(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseAutomaticHapticFeedback, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UseAutomaticHapticFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UseAutomaticHapticFeedback(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseAutomaticHapticFeedback, WINRT_WRAP(void), bool);
            this->shim().UseAutomaticHapticFeedback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ScreenContactStarted(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenContactStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScreenContactStarted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScreenContactStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScreenContactStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ScreenContactEnded(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenContactEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScreenContactEnded(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScreenContactEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScreenContactEnded(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ScreenContactContinued(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenContactContinued, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ScreenContactContinued(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScreenContactContinued(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScreenContactContinued, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScreenContactContinued(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ControlLost(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ControlLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ControlLost(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ControlLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ControlLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_RotationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerRotationChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RotationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerRotationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RotationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RotationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RotationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ButtonClicked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonClicked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonClickedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ButtonClicked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonClickedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ButtonClicked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ButtonClicked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ButtonClicked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ControlAcquired(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlAcquired, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ControlAcquired(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerControlAcquiredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ControlAcquired(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ControlAcquired, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ControlAcquired(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialController2> : produce_base<D, Windows::UI::Input::IRadialController2>
{
    int32_t WINRT_CALL add_ButtonPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonPressedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ButtonPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ButtonPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ButtonPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ButtonPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ButtonHolding(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonHolding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ButtonHolding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonHoldingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ButtonHolding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ButtonHolding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ButtonHolding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ButtonReleased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ButtonReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialController, Windows::UI::Input::RadialControllerButtonReleasedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ButtonReleased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ButtonReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ButtonReleased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerButtonClickedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerButtonClickedEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> : produce_base<D, Windows::UI::Input::IRadialControllerButtonClickedEventArgs2>
{
    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerButtonHoldingEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerButtonPressedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerButtonPressedEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerButtonReleasedEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerConfiguration> : produce_base<D, Windows::UI::Input::IRadialControllerConfiguration>
{
    int32_t WINRT_CALL SetDefaultMenuItems(void* buttons) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultMenuItems, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::RadialControllerSystemMenuItemKind> const&);
            this->shim().SetDefaultMenuItems(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::RadialControllerSystemMenuItemKind> const*>(&buttons));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetToDefaultMenuItems() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetToDefaultMenuItems, WINRT_WRAP(void));
            this->shim().ResetToDefaultMenuItems();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySelectDefaultMenuItem(Windows::UI::Input::RadialControllerSystemMenuItemKind type, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySelectDefaultMenuItem, WINRT_WRAP(bool), Windows::UI::Input::RadialControllerSystemMenuItemKind const&);
            *result = detach_from<bool>(this->shim().TrySelectDefaultMenuItem(*reinterpret_cast<Windows::UI::Input::RadialControllerSystemMenuItemKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerConfiguration2> : produce_base<D, Windows::UI::Input::IRadialControllerConfiguration2>
{
    int32_t WINRT_CALL put_ActiveControllerWhenMenuIsSuppressed(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActiveControllerWhenMenuIsSuppressed, WINRT_WRAP(void), Windows::UI::Input::RadialController const&);
            this->shim().ActiveControllerWhenMenuIsSuppressed(*reinterpret_cast<Windows::UI::Input::RadialController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActiveControllerWhenMenuIsSuppressed(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActiveControllerWhenMenuIsSuppressed, WINRT_WRAP(Windows::UI::Input::RadialController));
            *value = detach_from<Windows::UI::Input::RadialController>(this->shim().ActiveControllerWhenMenuIsSuppressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMenuSuppressed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMenuSuppressed, WINRT_WRAP(void), bool);
            this->shim().IsMenuSuppressed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMenuSuppressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMenuSuppressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMenuSuppressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerConfigurationStatics> : produce_base<D, Windows::UI::Input::IRadialControllerConfigurationStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** configuration) noexcept final
    {
        try
        {
            *configuration = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Input::RadialControllerConfiguration));
            *configuration = detach_from<Windows::UI::Input::RadialControllerConfiguration>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerConfigurationStatics2> : produce_base<D, Windows::UI::Input::IRadialControllerConfigurationStatics2>
{
    int32_t WINRT_CALL put_AppController(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppController, WINRT_WRAP(void), Windows::UI::Input::RadialController const&);
            this->shim().AppController(*reinterpret_cast<Windows::UI::Input::RadialController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppController, WINRT_WRAP(Windows::UI::Input::RadialController));
            *value = detach_from<Windows::UI::Input::RadialController>(this->shim().AppController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAppControllerEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppControllerEnabled, WINRT_WRAP(void), bool);
            this->shim().IsAppControllerEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAppControllerEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppControllerEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppControllerEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerControlAcquiredEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> : produce_base<D, Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2>
{
    int32_t WINRT_CALL get_IsButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerMenu> : produce_base<D, Windows::UI::Input::IRadialControllerMenu>
{
    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::RadialControllerMenuItem>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::RadialControllerMenuItem>>(this->shim().Items());
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

    int32_t WINRT_CALL GetSelectedMenuItem(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelectedMenuItem, WINRT_WRAP(Windows::UI::Input::RadialControllerMenuItem));
            *result = detach_from<Windows::UI::Input::RadialControllerMenuItem>(this->shim().GetSelectedMenuItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectMenuItem(void* menuItem) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectMenuItem, WINRT_WRAP(void), Windows::UI::Input::RadialControllerMenuItem const&);
            this->shim().SelectMenuItem(*reinterpret_cast<Windows::UI::Input::RadialControllerMenuItem const*>(&menuItem));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySelectPreviouslySelectedMenuItem(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySelectPreviouslySelectedMenuItem, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TrySelectPreviouslySelectedMenuItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerMenuItem> : produce_base<D, Windows::UI::Input::IRadialControllerMenuItem>
{
    int32_t WINRT_CALL get_DisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Tag(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Invoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialControllerMenuItem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::RadialControllerMenuItem, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Invoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Invoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerMenuItemStatics> : produce_base<D, Windows::UI::Input::IRadialControllerMenuItemStatics>
{
    int32_t WINRT_CALL CreateFromIcon(void* displayText, void* icon, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIcon, WINRT_WRAP(Windows::UI::Input::RadialControllerMenuItem), hstring const&, Windows::Storage::Streams::RandomAccessStreamReference const&);
            *result = detach_from<Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromIcon(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<Windows::Storage::Streams::RandomAccessStreamReference const*>(&icon)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromKnownIcon(void* displayText, Windows::UI::Input::RadialControllerMenuKnownIcon value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromKnownIcon, WINRT_WRAP(Windows::UI::Input::RadialControllerMenuItem), hstring const&, Windows::UI::Input::RadialControllerMenuKnownIcon const&);
            *result = detach_from<Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromKnownIcon(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<Windows::UI::Input::RadialControllerMenuKnownIcon const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerMenuItemStatics2> : produce_base<D, Windows::UI::Input::IRadialControllerMenuItemStatics2>
{
    int32_t WINRT_CALL CreateFromFontGlyph(void* displayText, void* glyph, void* fontFamily, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromFontGlyph, WINRT_WRAP(Windows::UI::Input::RadialControllerMenuItem), hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromFontGlyphWithUri(void* displayText, void* glyph, void* fontFamily, void* fontUri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromFontGlyph, WINRT_WRAP(Windows::UI::Input::RadialControllerMenuItem), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&);
            *result = detach_from<Windows::UI::Input::RadialControllerMenuItem>(this->shim().CreateFromFontGlyph(*reinterpret_cast<hstring const*>(&displayText), *reinterpret_cast<hstring const*>(&glyph), *reinterpret_cast<hstring const*>(&fontFamily), *reinterpret_cast<Windows::Foundation::Uri const*>(&fontUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerRotationChangedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerRotationChangedEventArgs>
{
    int32_t WINRT_CALL get_RotationDeltaInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationDeltaInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RotationDeltaInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> : produce_base<D, Windows::UI::Input::IRadialControllerRotationChangedEventArgs2>
{
    int32_t WINRT_CALL get_IsButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContact> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContact>
{
    int32_t WINRT_CALL get_Bounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2>
{
    int32_t WINRT_CALL get_IsButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs>
{
    int32_t WINRT_CALL get_IsButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs>
{
    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::UI::Input::RadialControllerScreenContact));
            *value = detach_from<Windows::UI::Input::RadialControllerScreenContact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> : produce_base<D, Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2>
{
    int32_t WINRT_CALL get_IsButtonPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsButtonPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsButtonPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimpleHapticsController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimpleHapticsController, WINRT_WRAP(Windows::Devices::Haptics::SimpleHapticsController));
            *value = detach_from<Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRadialControllerStatics> : produce_base<D, Windows::UI::Input::IRadialControllerStatics>
{
    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForCurrentView, WINRT_WRAP(Windows::UI::Input::RadialController));
            *result = detach_from<Windows::UI::Input::RadialController>(this->shim().CreateForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::IRightTappedEventArgs> : produce_base<D, Windows::UI::Input::IRightTappedEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::ITappedEventArgs> : produce_base<D, Windows::UI::Input::ITappedEventArgs>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TapCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TapCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TapCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input {

inline Windows::UI::Input::EdgeGesture EdgeGesture::GetForCurrentView()
{
    return impl::call_factory<EdgeGesture, Windows::UI::Input::IEdgeGestureStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline GestureRecognizer::GestureRecognizer() :
    GestureRecognizer(impl::call_factory<GestureRecognizer>([](auto&& f) { return f.template ActivateInstance<GestureRecognizer>(); }))
{}

inline Windows::UI::Input::KeyboardDeliveryInterceptor KeyboardDeliveryInterceptor::GetForCurrentView()
{
    return impl::call_factory<KeyboardDeliveryInterceptor, Windows::UI::Input::IKeyboardDeliveryInterceptorStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::UI::Input::PointerPoint PointerPoint::GetCurrentPoint(uint32_t pointerId)
{
    return impl::call_factory<PointerPoint, Windows::UI::Input::IPointerPointStatics>([&](auto&& f) { return f.GetCurrentPoint(pointerId); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> PointerPoint::GetIntermediatePoints(uint32_t pointerId)
{
    return impl::call_factory<PointerPoint, Windows::UI::Input::IPointerPointStatics>([&](auto&& f) { return f.GetIntermediatePoints(pointerId); });
}

inline Windows::UI::Input::PointerPoint PointerPoint::GetCurrentPoint(uint32_t pointerId, Windows::UI::Input::IPointerPointTransform const& transform)
{
    return impl::call_factory<PointerPoint, Windows::UI::Input::IPointerPointStatics>([&](auto&& f) { return f.GetCurrentPoint(pointerId, transform); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> PointerPoint::GetIntermediatePoints(uint32_t pointerId, Windows::UI::Input::IPointerPointTransform const& transform)
{
    return impl::call_factory<PointerPoint, Windows::UI::Input::IPointerPointStatics>([&](auto&& f) { return f.GetIntermediatePoints(pointerId, transform); });
}

inline Windows::UI::Input::PointerVisualizationSettings PointerVisualizationSettings::GetForCurrentView()
{
    return impl::call_factory<PointerVisualizationSettings, Windows::UI::Input::IPointerVisualizationSettingsStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline bool RadialController::IsSupported()
{
    return impl::call_factory<RadialController, Windows::UI::Input::IRadialControllerStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::UI::Input::RadialController RadialController::CreateForCurrentView()
{
    return impl::call_factory<RadialController, Windows::UI::Input::IRadialControllerStatics>([&](auto&& f) { return f.CreateForCurrentView(); });
}

inline Windows::UI::Input::RadialControllerConfiguration RadialControllerConfiguration::GetForCurrentView()
{
    return impl::call_factory<RadialControllerConfiguration, Windows::UI::Input::IRadialControllerConfigurationStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline void RadialControllerConfiguration::AppController(Windows::UI::Input::RadialController const& value)
{
    impl::call_factory<RadialControllerConfiguration, Windows::UI::Input::IRadialControllerConfigurationStatics2>([&](auto&& f) { return f.AppController(value); });
}

inline Windows::UI::Input::RadialController RadialControllerConfiguration::AppController()
{
    return impl::call_factory<RadialControllerConfiguration, Windows::UI::Input::IRadialControllerConfigurationStatics2>([&](auto&& f) { return f.AppController(); });
}

inline void RadialControllerConfiguration::IsAppControllerEnabled(bool value)
{
    impl::call_factory<RadialControllerConfiguration, Windows::UI::Input::IRadialControllerConfigurationStatics2>([&](auto&& f) { return f.IsAppControllerEnabled(value); });
}

inline bool RadialControllerConfiguration::IsAppControllerEnabled()
{
    return impl::call_factory<RadialControllerConfiguration, Windows::UI::Input::IRadialControllerConfigurationStatics2>([&](auto&& f) { return f.IsAppControllerEnabled(); });
}

inline Windows::UI::Input::RadialControllerMenuItem RadialControllerMenuItem::CreateFromIcon(param::hstring const& displayText, Windows::Storage::Streams::RandomAccessStreamReference const& icon)
{
    return impl::call_factory<RadialControllerMenuItem, Windows::UI::Input::IRadialControllerMenuItemStatics>([&](auto&& f) { return f.CreateFromIcon(displayText, icon); });
}

inline Windows::UI::Input::RadialControllerMenuItem RadialControllerMenuItem::CreateFromKnownIcon(param::hstring const& displayText, Windows::UI::Input::RadialControllerMenuKnownIcon const& value)
{
    return impl::call_factory<RadialControllerMenuItem, Windows::UI::Input::IRadialControllerMenuItemStatics>([&](auto&& f) { return f.CreateFromKnownIcon(displayText, value); });
}

inline Windows::UI::Input::RadialControllerMenuItem RadialControllerMenuItem::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily)
{
    return impl::call_factory<RadialControllerMenuItem, Windows::UI::Input::IRadialControllerMenuItemStatics2>([&](auto&& f) { return f.CreateFromFontGlyph(displayText, glyph, fontFamily); });
}

inline Windows::UI::Input::RadialControllerMenuItem RadialControllerMenuItem::CreateFromFontGlyph(param::hstring const& displayText, param::hstring const& glyph, param::hstring const& fontFamily, Windows::Foundation::Uri const& fontUri)
{
    return impl::call_factory<RadialControllerMenuItem, Windows::UI::Input::IRadialControllerMenuItemStatics2>([&](auto&& f) { return f.CreateFromFontGlyph(displayText, glyph, fontFamily, fontUri); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::IAttachableInputObject> : winrt::impl::hash_base<winrt::Windows::UI::Input::IAttachableInputObject> {};
template<> struct hash<winrt::Windows::UI::Input::IAttachableInputObjectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::IAttachableInputObjectFactory> {};
template<> struct hash<winrt::Windows::UI::Input::ICrossSlidingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ICrossSlidingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IDraggingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IDraggingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IEdgeGesture> : winrt::impl::hash_base<winrt::Windows::UI::Input::IEdgeGesture> {};
template<> struct hash<winrt::Windows::UI::Input::IEdgeGestureEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IEdgeGestureEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IEdgeGestureStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IEdgeGestureStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IGestureRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::IGestureRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::IHoldingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IHoldingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IInputActivationListener> : winrt::impl::hash_base<winrt::Windows::UI::Input::IInputActivationListener> {};
template<> struct hash<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IInputActivationListenerActivationChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor> : winrt::impl::hash_base<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptor> {};
template<> struct hash<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IKeyboardDeliveryInterceptorStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IManipulationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IManipulationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IManipulationInertiaStartingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IManipulationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IManipulationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IManipulationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IMouseWheelParameters> : winrt::impl::hash_base<winrt::Windows::UI::Input::IMouseWheelParameters> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerPoint> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerPoint> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerPointProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerPointProperties> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerPointProperties2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerPointProperties2> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerPointStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerPointStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerPointTransform> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerPointTransform> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerVisualizationSettings> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerVisualizationSettings> {};
template<> struct hash<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IPointerVisualizationSettingsStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialController> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialController> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialController2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialController2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerButtonClickedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerButtonHoldingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerButtonPressedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerButtonReleasedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfiguration2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerConfiguration2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerConfigurationStatics2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerControlAcquiredEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenu> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerMenu> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItem> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerMenuItem> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerMenuItemStatics2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerRotationChangedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContact> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContact> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContactContinuedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContactEndedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerScreenContactStartedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::IRadialControllerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRadialControllerStatics> {};
template<> struct hash<winrt::Windows::UI::Input::IRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::IRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::ITappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ITappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::AttachableInputObject> : winrt::impl::hash_base<winrt::Windows::UI::Input::AttachableInputObject> {};
template<> struct hash<winrt::Windows::UI::Input::CrossSlidingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::CrossSlidingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::DraggingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::DraggingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::EdgeGesture> : winrt::impl::hash_base<winrt::Windows::UI::Input::EdgeGesture> {};
template<> struct hash<winrt::Windows::UI::Input::EdgeGestureEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::EdgeGestureEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::GestureRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::GestureRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::HoldingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::HoldingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::InputActivationListener> : winrt::impl::hash_base<winrt::Windows::UI::Input::InputActivationListener> {};
template<> struct hash<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::InputActivationListenerActivationChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor> : winrt::impl::hash_base<winrt::Windows::UI::Input::KeyboardDeliveryInterceptor> {};
template<> struct hash<winrt::Windows::UI::Input::ManipulationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ManipulationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ManipulationInertiaStartingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::ManipulationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ManipulationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::ManipulationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::MouseWheelParameters> : winrt::impl::hash_base<winrt::Windows::UI::Input::MouseWheelParameters> {};
template<> struct hash<winrt::Windows::UI::Input::PointerPoint> : winrt::impl::hash_base<winrt::Windows::UI::Input::PointerPoint> {};
template<> struct hash<winrt::Windows::UI::Input::PointerPointProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::PointerPointProperties> {};
template<> struct hash<winrt::Windows::UI::Input::PointerVisualizationSettings> : winrt::impl::hash_base<winrt::Windows::UI::Input::PointerVisualizationSettings> {};
template<> struct hash<winrt::Windows::UI::Input::RadialController> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialController> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerButtonClickedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerButtonHoldingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerButtonPressedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerButtonReleasedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerConfiguration> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerControlAcquiredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerMenu> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerMenu> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerMenuItem> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerMenuItem> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerRotationChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContact> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerScreenContact> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerScreenContactContinuedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerScreenContactEndedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RadialControllerScreenContactStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::RightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::RightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::TappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::TappedEventArgs> {};

}
