// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
#include "winrt/impl/Windows.Devices.Power.2.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Perception.People.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Input.Spatial.2.h"
#include "winrt/Windows.UI.Input.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_RecognitionStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RecognitionStarted_revoker>(this, RecognitionStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_RecognitionStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_RecognitionEnded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RecognitionEnded_revoker>(this, RecognitionEnded(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::RecognitionEnded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_RecognitionEnded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialTappedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_Tapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialTappedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::Tapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_Tapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HoldStarted_revoker>(this, HoldStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HoldCompleted_revoker>(this, HoldCompleted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_HoldCanceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HoldCanceled_revoker>(this, HoldCanceled(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::HoldCanceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_HoldCanceled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationUpdated_revoker>(this, ManipulationUpdated(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_ManipulationCanceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ManipulationCanceled_revoker>(this, ManipulationCanceled(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::ManipulationCanceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_ManipulationCanceled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationStarted_revoker>(this, NavigationStarted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationUpdated_revoker>(this, NavigationUpdated(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationCompleted_revoker>(this, NavigationCompleted(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->add_NavigationCanceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled_revoker consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationCanceled_revoker>(this, NavigationCanceled(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::NavigationCanceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->remove_NavigationCanceled(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::CaptureInteraction(Windows::UI::Input::Spatial::SpatialInteraction const& interaction) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->CaptureInteraction(get_abi(interaction)));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::CancelPendingGestures() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->CancelPendingGestures());
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::TrySetGestureSettings(Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->TrySetGestureSettings(get_abi(settings), &succeeded));
    return succeeded;
}

template <typename D> Windows::UI::Input::Spatial::SpatialGestureSettings consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizer<D>::GestureSettings() const
{
    Windows::UI::Input::Spatial::SpatialGestureSettings value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizer)->get_GestureSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialGestureRecognizer consume_Windows_UI_Input_Spatial_ISpatialGestureRecognizerFactory<D>::Create(Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) const
{
    Windows::UI::Input::Spatial::SpatialGestureRecognizer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory)->Create(get_abi(settings), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialHoldCanceledEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialHoldCompletedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialHoldStartedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialHoldStartedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceState consume_Windows_UI_Input_Spatial_ISpatialInteraction<D>::SourceState() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteraction)->get_SourceState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::HasTouchpad() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_HasTouchpad(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::HasThumbstick() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_HasThumbstick(&value));
    return value;
}

template <typename D> Windows::Devices::Haptics::SimpleHapticsController consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::SimpleHapticsController() const
{
    Windows::Devices::Haptics::SimpleHapticsController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_SimpleHapticsController(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::VendorId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_VendorId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::ProductId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_ProductId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_UI_Input_Spatial_ISpatialInteractionController<D>::Version() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController)->get_Version(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> consume_Windows_UI_Input_Spatial_ISpatialInteractionController2<D>::TryGetRenderableModelAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController2)->TryGetRenderableModelAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Power::BatteryReport consume_Windows_UI_Input_Spatial_ISpatialInteractionController3<D>::TryGetBatteryReport() const
{
    Windows::Devices::Power::BatteryReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionController3)->TryGetBatteryReport(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsTouchpadTouched() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsTouchpadTouched(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsTouchpadPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsTouchpadPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::IsThumbstickPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_IsThumbstickPressed(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::ThumbstickX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_ThumbstickX(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::ThumbstickY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_ThumbstickY(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::TouchpadX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_TouchpadX(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionControllerProperties<D>::TouchpadY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties)->get_TouchpadY(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteraction consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs<D>::Interaction() const
{
    Windows::UI::Input::Spatial::SpatialInteraction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs)->get_Interaction(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSource consume_Windows_UI_Input_Spatial_ISpatialInteractionDetectedEventArgs2<D>::InteractionSource() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2)->get_InteractionSource(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceDetected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceDetected_revoker>(this, SourceDetected(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceDetected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceDetected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceLost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceLost_revoker>(this, SourceLost(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceLost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceLost(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceUpdated_revoker>(this, SourceUpdated(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourcePressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourcePressed_revoker>(this, SourcePressed(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourcePressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourcePressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_SourceReleased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SourceReleased_revoker>(this, SourceReleased(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::SourceReleased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_SourceReleased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->add_InteractionDetected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected_revoker consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InteractionDetected_revoker>(this, InteractionDetected(handler));
}

template <typename D> void consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::InteractionDetected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->remove_InteractionDetected(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Spatial::SpatialInteractionSourceState> consume_Windows_UI_Input_Spatial_ISpatialInteractionManager<D>::GetDetectedSourcesAtTimestamp(Windows::Perception::PerceptionTimestamp const& timeStamp) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Spatial::SpatialInteractionSourceState> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManager)->GetDetectedSourcesAtTimestamp(get_abi(timeStamp), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionManager consume_Windows_UI_Input_Spatial_ISpatialInteractionManagerStatics<D>::GetForCurrentView() const
{
    Windows::UI::Input::Spatial::SpatialInteractionManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionManagerStatics2<D>::IsSourceKindSupported(Windows::UI::Input::Spatial::SpatialInteractionSourceKind const& kind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2)->IsSourceKindSupported(get_abi(kind), &result));
    return result;
}

template <typename D> uint32_t consume_Windows_UI_Input_Spatial_ISpatialInteractionSource<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource)->get_Id(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialInteractionSource<D>::Kind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsPointingSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsPointingSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsMenuSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsMenuSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::IsGraspSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_IsGraspSupported(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionController consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::Controller() const
{
    Windows::UI::Input::Spatial::SpatialInteractionController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource2)->get_Controller(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceState consume_Windows_UI_Input_Spatial_ISpatialInteractionSource2<D>::TryGetStateAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp) const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource2)->TryGetStateAtTimestamp(get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness consume_Windows_UI_Input_Spatial_ISpatialInteractionSource3<D>::Handedness() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource3)->get_Handedness(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::People::HandMeshObserver consume_Windows_UI_Input_Spatial_ISpatialInteractionSource4<D>::TryCreateHandMeshObserver() const
{
    Windows::Perception::People::HandMeshObserver result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource4)->TryCreateHandMeshObserver(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::People::HandMeshObserver> consume_Windows_UI_Input_Spatial_ISpatialInteractionSource4<D>::TryCreateHandMeshObserverAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::People::HandMeshObserver> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSource4)->TryCreateHandMeshObserverAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceState consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceEventArgs<D>::State() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionPressKind consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceEventArgs2<D>::PressKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionPressKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2)->get_PressKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation<D>::Position() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation<D>::Velocity() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation)->get_Velocity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::quaternion> consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation2<D>::Orientation() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::quaternion> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::PositionAccuracy() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_PositionAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::AngularVelocity() const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_AngularVelocity(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceLocation3<D>::SourcePointerPose() const
{
    Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3)->get_SourcePointerPose(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::TryGetSourceLossMitigationDirection(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float3> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->TryGetSourceLossMitigationDirection(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::SourceLossRisk() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->get_SourceLossRisk(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceLocation consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceProperties<D>::TryGetLocation(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceLocation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties)->TryGetLocation(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSource consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Source() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Source(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceProperties consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Properties() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::IsPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_IsPressed(&value));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::Timestamp() const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsSelectPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsSelectPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsMenuPressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsMenuPressed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::IsGrasped() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_IsGrasped(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::SelectPressedValue() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_SelectPressedValue(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionControllerProperties consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState2<D>::ControllerProperties() const
{
    Windows::UI::Input::Spatial::SpatialInteractionControllerProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState2)->get_ControllerProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::People::HandPose consume_Windows_UI_Input_Spatial_ISpatialInteractionSourceState3<D>::TryGetHandPose() const
{
    Windows::Perception::People::HandPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialInteractionSourceState3)->TryGetHandPose(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialManipulationCanceledEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialManipulationCompletedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialManipulationDelta consume_Windows_UI_Input_Spatial_ISpatialManipulationCompletedEventArgs<D>::TryGetCumulativeDelta(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialManipulationDelta value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs)->TryGetCumulativeDelta(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialManipulationDelta<D>::Translation() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationDelta)->get_Translation(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialManipulationStartedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialManipulationStartedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialManipulationUpdatedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialManipulationDelta consume_Windows_UI_Input_Spatial_ISpatialManipulationUpdatedEventArgs<D>::TryGetCumulativeDelta(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialManipulationDelta value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs)->TryGetCumulativeDelta(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialNavigationCanceledEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialNavigationCompletedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialNavigationCompletedEventArgs<D>::NormalizedOffset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs)->get_NormalizedOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingX() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingX(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingY() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingY(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialNavigationStartedEventArgs<D>::IsNavigatingZ() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs)->get_IsNavigatingZ(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialNavigationUpdatedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialNavigationUpdatedEventArgs<D>::NormalizedOffset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs)->get_NormalizedOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::ForwardDirection() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_ForwardDirection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose<D>::UpDirection() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose)->get_UpDirection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose2<D>::Orientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy consume_Windows_UI_Input_Spatial_ISpatialPointerInteractionSourcePose2<D>::PositionAccuracy() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2)->get_PositionAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_UI_Input_Spatial_ISpatialPointerPose<D>::Timestamp() const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPose)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::People::HeadPose consume_Windows_UI_Input_Spatial_ISpatialPointerPose<D>::Head() const
{
    Windows::Perception::People::HeadPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPose)->get_Head(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose consume_Windows_UI_Input_Spatial_ISpatialPointerPose2<D>::TryGetInteractionSourcePose(Windows::UI::Input::Spatial::SpatialInteractionSource const& source) const
{
    Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPose2)->TryGetInteractionSourcePose(get_abi(source), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::People::EyesPose consume_Windows_UI_Input_Spatial_ISpatialPointerPose3<D>::Eyes() const
{
    Windows::Perception::People::EyesPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPose3)->get_Eyes(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialPointerPose3<D>::IsHeadCapturedBySystem() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPose3)->get_IsHeadCapturedBySystem(&value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialPointerPoseStatics<D>::TryGetAtTimestamp(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::PerceptionTimestamp const& timestamp) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialPointerPoseStatics)->TryGetAtTimestamp(get_abi(coordinateSystem), get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialRecognitionEndedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Spatial_ISpatialRecognitionStartedEventArgs<D>::IsGesturePossible(Windows::UI::Input::Spatial::SpatialGestureSettings const& gesture) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs)->IsGesturePossible(get_abi(gesture), &value));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSourceKind consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::InteractionSourceKind() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSourceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->get_InteractionSourceKind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Spatial::SpatialPointerPose consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::TryGetPointerPose(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::UI::Input::Spatial::SpatialPointerPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->TryGetPointerPose(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_Spatial_ISpatialTappedEventArgs<D>::TapCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Spatial::ISpatialTappedEventArgs)->get_TapCount(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialGestureRecognizer> : produce_base<D, Windows::UI::Input::Spatial::ISpatialGestureRecognizer>
{
    int32_t WINRT_CALL add_RecognitionStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognitionStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecognitionStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecognitionStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecognitionStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecognitionStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RecognitionEnded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognitionEnded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecognitionEnded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecognitionEnded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecognitionEnded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecognitionEnded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Tapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialTappedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialTappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Tapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HoldStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HoldStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HoldStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HoldStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HoldStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HoldCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HoldCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HoldCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HoldCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HoldCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HoldCanceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HoldCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HoldCanceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HoldCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HoldCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationCanceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationCanceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NavigationStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NavigationUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NavigationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NavigationCanceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialGestureRecognizer, Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationCanceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CaptureInteraction(void* interaction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureInteraction, WINRT_WRAP(void), Windows::UI::Input::Spatial::SpatialInteraction const&);
            this->shim().CaptureInteraction(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialInteraction const*>(&interaction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelPendingGestures() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelPendingGestures, WINRT_WRAP(void));
            this->shim().CancelPendingGestures();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetGestureSettings(Windows::UI::Input::Spatial::SpatialGestureSettings settings, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetGestureSettings, WINRT_WRAP(bool), Windows::UI::Input::Spatial::SpatialGestureSettings const&);
            *succeeded = detach_from<bool>(this->shim().TrySetGestureSettings(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GestureSettings(Windows::UI::Input::Spatial::SpatialGestureSettings* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GestureSettings, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialGestureSettings));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialGestureSettings>(this->shim().GestureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory> : produce_base<D, Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory>
{
    int32_t WINRT_CALL Create(Windows::UI::Input::Spatial::SpatialGestureSettings settings, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialGestureRecognizer), Windows::UI::Input::Spatial::SpatialGestureSettings const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialGestureRecognizer>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteraction> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteraction>
{
    int32_t WINRT_CALL get_SourceState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceState, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceState));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().SourceState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionController> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionController>
{
    int32_t WINRT_CALL get_HasTouchpad(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasTouchpad, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasTouchpad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasThumbstick(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasThumbstick, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasThumbstick());
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

    int32_t WINRT_CALL get_VendorId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VendorId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().VendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Version(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionController2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionController2>
{
    int32_t WINRT_CALL TryGetRenderableModelAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetRenderableModelAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamWithContentType>>(this->shim().TryGetRenderableModelAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionController3> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionController3>
{
    int32_t WINRT_CALL TryGetBatteryReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetBatteryReport, WINRT_WRAP(Windows::Devices::Power::BatteryReport));
            *value = detach_from<Windows::Devices::Power::BatteryReport>(this->shim().TryGetBatteryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties>
{
    int32_t WINRT_CALL get_IsTouchpadTouched(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTouchpadTouched, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTouchpadTouched());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTouchpadPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTouchpadPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTouchpadPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsThumbstickPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThumbstickPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsThumbstickPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbstickX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbstickX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ThumbstickX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThumbstickY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbstickY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ThumbstickY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TouchpadX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchpadX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TouchpadX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TouchpadY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchpadY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TouchpadY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interaction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interaction, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteraction));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteraction>(this->shim().Interaction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2>
{
    int32_t WINRT_CALL get_InteractionSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSource, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSource));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSource>(this->shim().InteractionSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionManager> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionManager>
{
    int32_t WINRT_CALL add_SourceDetected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceDetected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceDetected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceDetected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceLost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceLost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceLost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourcePressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourcePressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourcePressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourcePressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourcePressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SourceReleased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SourceReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceReleased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceReleased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_InteractionDetected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().InteractionDetected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Spatial::SpatialInteractionManager, Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InteractionDetected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InteractionDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InteractionDetected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetDetectedSourcesAtTimestamp(void* timeStamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDetectedSourcesAtTimestamp, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Spatial::SpatialInteractionSourceState>), Windows::Perception::PerceptionTimestamp const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Spatial::SpatialInteractionSourceState>>(this->shim().GetDetectedSourcesAtTimestamp(*reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timeStamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionManager));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2>
{
    int32_t WINRT_CALL IsSourceKindSupported(Windows::UI::Input::Spatial::SpatialInteractionSourceKind kind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSourceKindSupported, WINRT_WRAP(bool), Windows::UI::Input::Spatial::SpatialInteractionSourceKind const&);
            *result = detach_from<bool>(this->shim().IsSourceKindSupported(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialInteractionSourceKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSource> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSource>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSource2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSource2>
{
    int32_t WINRT_CALL get_IsPointingSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPointingSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPointingSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMenuSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMenuSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMenuSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGraspSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGraspSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGraspSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Controller(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionController));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetStateAtTimestamp(void* timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetStateAtTimestamp, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceState), Windows::Perception::PerceptionTimestamp const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().TryGetStateAtTimestamp(*reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSource3> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSource3>
{
    int32_t WINRT_CALL get_Handedness(Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handedness, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceHandedness>(this->shim().Handedness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSource4> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSource4>
{
    int32_t WINRT_CALL TryCreateHandMeshObserver(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateHandMeshObserver, WINRT_WRAP(Windows::Perception::People::HandMeshObserver));
            *result = detach_from<Windows::Perception::People::HandMeshObserver>(this->shim().TryCreateHandMeshObserver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateHandMeshObserverAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateHandMeshObserverAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::People::HandMeshObserver>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::People::HandMeshObserver>>(this->shim().TryCreateHandMeshObserverAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs>
{
    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceState));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2>
{
    int32_t WINRT_CALL get_PressKind(Windows::UI::Input::Spatial::SpatialInteractionPressKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PressKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionPressKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionPressKind>(this->shim().PressKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation>
{
    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Velocity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Velocity, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().Velocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2>
{
    int32_t WINRT_CALL get_Orientation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::quaternion>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::quaternion>>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3>
{
    int32_t WINRT_CALL get_PositionAccuracy(Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionAccuracy, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy>(this->shim().PositionAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AngularVelocity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngularVelocity, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().AngularVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePointerPose(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose>(this->shim().SourcePointerPose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties>
{
    int32_t WINRT_CALL TryGetSourceLossMitigationDirection(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetSourceLossMitigationDirection, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float3>>(this->shim().TryGetSourceLossMitigationDirection(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceLossRisk(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceLossRisk, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SourceLossRisk());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetLocation(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetLocation, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceLocation), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceLocation>(this->shim().TryGetLocation(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSource));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSource>(this->shim().Source());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceProperties));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceProperties>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Perception::PerceptionTimestamp));
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState2>
{
    int32_t WINRT_CALL get_IsSelectPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelectPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMenuPressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMenuPressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMenuPressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGrasped(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGrasped, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGrasped());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectPressedValue(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectPressedValue, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SelectPressedValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControllerProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControllerProperties, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionControllerProperties));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionControllerProperties>(this->shim().ControllerProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState3> : produce_base<D, Windows::UI::Input::Spatial::ISpatialInteractionSourceState3>
{
    int32_t WINRT_CALL TryGetHandPose(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetHandPose, WINRT_WRAP(Windows::Perception::People::HandPose));
            *value = detach_from<Windows::Perception::People::HandPose>(this->shim().TryGetHandPose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetCumulativeDelta(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetCumulativeDelta, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialManipulationDelta), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialManipulationDelta>(this->shim().TryGetCumulativeDelta(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialManipulationDelta> : produce_base<D, Windows::UI::Input::Spatial::ISpatialManipulationDelta>
{
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
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetCumulativeDelta(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetCumulativeDelta, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialManipulationDelta), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialManipulationDelta>(this->shim().TryGetCumulativeDelta(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedOffset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedOffset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().NormalizedOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNavigatingX(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNavigatingX, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNavigatingX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNavigatingY(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNavigatingY, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNavigatingY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNavigatingZ(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNavigatingZ, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNavigatingZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedOffset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedOffset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().NormalizedOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose>
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

    int32_t WINRT_CALL get_ForwardDirection(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardDirection, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().ForwardDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpDirection(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpDirection, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().UpDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2>
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

    int32_t WINRT_CALL get_PositionAccuracy(Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionAccuracy, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourcePositionAccuracy>(this->shim().PositionAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerPose> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerPose>
{
    int32_t WINRT_CALL get_Timestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Perception::PerceptionTimestamp));
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Head(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Head, WINRT_WRAP(Windows::Perception::People::HeadPose));
            *value = detach_from<Windows::Perception::People::HeadPose>(this->shim().Head());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerPose2> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerPose2>
{
    int32_t WINRT_CALL TryGetInteractionSourcePose(void* source, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetInteractionSourcePose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose), Windows::UI::Input::Spatial::SpatialInteractionSource const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose>(this->shim().TryGetInteractionSourcePose(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialInteractionSource const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerPose3> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerPose3>
{
    int32_t WINRT_CALL get_Eyes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Eyes, WINRT_WRAP(Windows::Perception::People::EyesPose));
            *value = detach_from<Windows::Perception::People::EyesPose>(this->shim().Eyes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHeadCapturedBySystem(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHeadCapturedBySystem, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHeadCapturedBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialPointerPoseStatics> : produce_base<D, Windows::UI::Input::Spatial::ISpatialPointerPoseStatics>
{
    int32_t WINRT_CALL TryGetAtTimestamp(void* coordinateSystem, void* timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAtTimestamp, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::PerceptionTimestamp const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetAtTimestamp(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsGesturePossible(Windows::UI::Input::Spatial::SpatialGestureSettings gesture, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGesturePossible, WINRT_WRAP(bool), Windows::UI::Input::Spatial::SpatialGestureSettings const&);
            *value = detach_from<bool>(this->shim().IsGesturePossible(*reinterpret_cast<Windows::UI::Input::Spatial::SpatialGestureSettings const*>(&gesture)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Spatial::ISpatialTappedEventArgs> : produce_base<D, Windows::UI::Input::Spatial::ISpatialTappedEventArgs>
{
    int32_t WINRT_CALL get_InteractionSourceKind(Windows::UI::Input::Spatial::SpatialInteractionSourceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InteractionSourceKind, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSourceKind));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSourceKind>(this->shim().InteractionSourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetPointerPose(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPointerPose, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialPointerPose), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::UI::Input::Spatial::SpatialPointerPose>(this->shim().TryGetPointerPose(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
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

WINRT_EXPORT namespace winrt::Windows::UI::Input::Spatial {

inline SpatialGestureRecognizer::SpatialGestureRecognizer(Windows::UI::Input::Spatial::SpatialGestureSettings const& settings) :
    SpatialGestureRecognizer(impl::call_factory<SpatialGestureRecognizer, Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory>([&](auto&& f) { return f.Create(settings); }))
{}

inline Windows::UI::Input::Spatial::SpatialInteractionManager SpatialInteractionManager::GetForCurrentView()
{
    return impl::call_factory<SpatialInteractionManager, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline bool SpatialInteractionManager::IsSourceKindSupported(Windows::UI::Input::Spatial::SpatialInteractionSourceKind const& kind)
{
    return impl::call_factory<SpatialInteractionManager, Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2>([&](auto&& f) { return f.IsSourceKindSupported(kind); });
}

inline Windows::UI::Input::Spatial::SpatialPointerPose SpatialPointerPose::TryGetAtTimestamp(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::PerceptionTimestamp const& timestamp)
{
    return impl::call_factory<SpatialPointerPose, Windows::UI::Input::Spatial::ISpatialPointerPoseStatics>([&](auto&& f) { return f.TryGetAtTimestamp(coordinateSystem, timestamp); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialGestureRecognizerFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialHoldCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialHoldCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialHoldStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteraction> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteraction> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionController3> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionControllerProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionDetectedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManager> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource3> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSource4> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceLocation3> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialInteractionSourceState3> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialManipulationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialManipulationDelta> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialManipulationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialManipulationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialNavigationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialNavigationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialNavigationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerInteractionSourcePose2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose2> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerPose3> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialPointerPoseStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionEndedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialRecognitionStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::ISpatialTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialGestureRecognizer> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialHoldCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialHoldCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialHoldStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteraction> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteraction> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionController> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionController> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionControllerProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionDetectedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionManager> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionSource> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceLocation> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceProperties> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialInteractionSourceState> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialManipulationCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialManipulationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialManipulationDelta> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialManipulationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialManipulationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialNavigationCanceledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialNavigationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialNavigationStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialNavigationUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialPointerInteractionSourcePose> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialPointerPose> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialPointerPose> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialRecognitionEndedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialRecognitionStartedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Spatial::SpatialTappedEventArgs> {};

}
