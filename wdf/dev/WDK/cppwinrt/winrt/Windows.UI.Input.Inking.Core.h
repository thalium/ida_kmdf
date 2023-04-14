// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.Core.2.h"
#include "winrt/Windows.UI.Input.Inking.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>::AppendInkPoints(param::iterable<Windows::UI::Input::Inking::InkPoint> const& inkPoints) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke)->AppendInkPoints(get_abi(inkPoints), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::InkStroke consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>::CreateInkStroke() const
{
    Windows::UI::Input::Inking::InkStroke result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke)->CreateInkStroke(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::InkDrawingAttributes consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>::DrawingAttributes() const
{
    Windows::UI::Input::Inking::InkDrawingAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke)->get_DrawingAttributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3x2 consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>::PointTransform() const
{
    Windows::Foundation::Numerics::float3x2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke)->get_PointTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStroke<D>::BoundingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke)->get_BoundingRect(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke consume_Windows_UI_Input_Inking_Core_ICoreIncrementalInkStrokeFactory<D>::Create(Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes, Windows::Foundation::Numerics::float3x2 const& pointTransform) const
{
    Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory)->Create(get_abi(drawingAttributes), get_abi(pointTransform), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerEntering(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerEntering(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerEntering_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerEntering(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerEntering_revoker>(this, PointerEntering(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerEntering(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerEntering(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerHovering(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerHovering(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerHovering_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerHovering(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerHovering_revoker>(this, PointerHovering(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerHovering(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerHovering(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerExiting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerExiting(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerExiting_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerExiting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerExiting_revoker>(this, PointerExiting(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerExiting(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerExiting(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerPressing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerPressing(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerPressing_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerPressing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerPressing_revoker>(this, PointerPressing(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerPressing(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerPressing(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerMoving(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerMoving(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerMoving_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerMoving(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerMoving_revoker>(this, PointerMoving(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerMoving(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerMoving(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerReleasing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerReleasing(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerReleasing_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerReleasing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerReleasing_revoker>(this, PointerReleasing(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerReleasing(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerReleasing(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerLost(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->add_PointerLost(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerLost_revoker consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerLost_revoker>(this, PointerLost(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::PointerLost(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->remove_PointerLost(get_abi(cookie)));
}

template <typename D> Windows::UI::Input::Inking::InkPresenter consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSource<D>::InkPresenter() const
{
    Windows::UI::Input::Inking::InkPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource)->get_InkPresenter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource consume_Windows_UI_Input_Inking_Core_ICoreInkIndependentInputSourceStatics<D>::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
{
    Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource inkIndependentInputSource{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics)->Create(get_abi(inkPresenter), put_abi(inkIndependentInputSource)));
    return inkIndependentInputSource;
}

template <typename D> Windows::UI::Input::Inking::InkPresenter consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost<D>::InkPresenter() const
{
    Windows::UI::Input::Inking::InkPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkPresenterHost)->get_InkPresenter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::ContainerVisual consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost<D>::RootVisual() const
{
    Windows::UI::Composition::ContainerVisual value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkPresenterHost)->get_RootVisual(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreInkPresenterHost<D>::RootVisual(Windows::UI::Composition::ContainerVisual const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreInkPresenterHost)->put_RootVisual(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::Inking::InkPoint> consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>::NewInkPoints() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::Inking::InkPoint> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs)->get_NewInkPoints(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>::PointerId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs)->get_PointerId(&value));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>::Disposition() const
{
    Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs)->get_Disposition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateEventArgs<D>::Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs)->put_Disposition(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStarting(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->add_WetStrokeStarting(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStarting_revoker consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WetStrokeStarting_revoker>(this, WetStrokeStarting(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStarting(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->remove_WetStrokeStarting(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeContinuing(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->add_WetStrokeContinuing(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeContinuing_revoker consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeContinuing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WetStrokeContinuing_revoker>(this, WetStrokeContinuing(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeContinuing(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->remove_WetStrokeContinuing(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStopping(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->add_WetStrokeStopping(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStopping_revoker consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStopping(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WetStrokeStopping_revoker>(this, WetStrokeStopping(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeStopping(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->remove_WetStrokeStopping(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->add_WetStrokeCompleted(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCompleted_revoker consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WetStrokeCompleted_revoker>(this, WetStrokeCompleted(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCompleted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->remove_WetStrokeCompleted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->add_WetStrokeCanceled(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCanceled_revoker consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WetStrokeCanceled_revoker>(this, WetStrokeCanceled(handler));
}

template <typename D> void consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::WetStrokeCanceled(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->remove_WetStrokeCanceled(get_abi(cookie)));
}

template <typename D> Windows::UI::Input::Inking::InkPresenter consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSource<D>::InkPresenter() const
{
    Windows::UI::Input::Inking::InkPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource)->get_InkPresenter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource consume_Windows_UI_Input_Inking_Core_ICoreWetStrokeUpdateSourceStatics<D>::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter) const
{
    Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource WetStrokeUpdateSource{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics)->Create(get_abi(inkPresenter), put_abi(WetStrokeUpdateSource)));
    return WetStrokeUpdateSource;
}

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke>
{
    int32_t WINRT_CALL AppendInkPoints(void* inkPoints, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendInkPoints, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().AppendInkPoints(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkPoint> const*>(&inkPoints)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInkStroke(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInkStroke, WINRT_WRAP(Windows::UI::Input::Inking::InkStroke));
            *result = detach_from<Windows::UI::Input::Inking::InkStroke>(this->shim().CreateInkStroke());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DrawingAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawingAttributes, WINRT_WRAP(Windows::UI::Input::Inking::InkDrawingAttributes));
            *value = detach_from<Windows::UI::Input::Inking::InkDrawingAttributes>(this->shim().DrawingAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointTransform(Windows::Foundation::Numerics::float3x2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointTransform, WINRT_WRAP(Windows::Foundation::Numerics::float3x2));
            *value = detach_from<Windows::Foundation::Numerics::float3x2>(this->shim().PointTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>
{
    int32_t WINRT_CALL Create(void* drawingAttributes, Windows::Foundation::Numerics::float3x2 pointTransform, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke), Windows::UI::Input::Inking::InkDrawingAttributes const&, Windows::Foundation::Numerics::float3x2 const&);
            *result = detach_from<Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Inking::InkDrawingAttributes const*>(&drawingAttributes), *reinterpret_cast<Windows::Foundation::Numerics::float3x2 const*>(&pointTransform)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource>
{
    int32_t WINRT_CALL add_PointerEntering(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEntering, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntering(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerEntering(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerEntering, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerEntering(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerHovering(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerHovering, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerHovering(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerHovering(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerHovering, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerHovering(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerExiting(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExiting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExiting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerExiting(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerExiting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerExiting(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerPressing(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerPressing(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerPressing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerPressing(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerMoving(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMoving, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoving(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerMoving(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerMoving, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerMoving(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerReleasing(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleasing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleasing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerReleasing(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerReleasing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerReleasing(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerLost(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerLost(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_InkPresenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InkPresenter, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenter));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>
{
    int32_t WINRT_CALL Create(void* inkPresenter, void** inkIndependentInputSource) noexcept final
    {
        try
        {
            *inkIndependentInputSource = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource), Windows::UI::Input::Inking::InkPresenter const&);
            *inkIndependentInputSource = detach_from<Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreInkPresenterHost> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreInkPresenterHost>
{
    int32_t WINRT_CALL get_InkPresenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InkPresenter, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenter));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RootVisual(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RootVisual, WINRT_WRAP(Windows::UI::Composition::ContainerVisual));
            *value = detach_from<Windows::UI::Composition::ContainerVisual>(this->shim().RootVisual());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RootVisual(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RootVisual, WINRT_WRAP(void), Windows::UI::Composition::ContainerVisual const&);
            this->shim().RootVisual(*reinterpret_cast<Windows::UI::Composition::ContainerVisual const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs>
{
    int32_t WINRT_CALL get_NewInkPoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewInkPoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::Inking::InkPoint>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::Inking::InkPoint>>(this->shim().NewInkPoints());
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

    int32_t WINRT_CALL get_Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disposition, WINRT_WRAP(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition));
            *value = detach_from<Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition>(this->shim().Disposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Disposition(Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disposition, WINRT_WRAP(void), Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition const&);
            this->shim().Disposition(*reinterpret_cast<Windows::UI::Input::Inking::Core::CoreWetStrokeDisposition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource>
{
    int32_t WINRT_CALL add_WetStrokeStarting(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WetStrokeStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().WetStrokeStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WetStrokeStarting(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WetStrokeStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WetStrokeStarting(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_WetStrokeContinuing(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WetStrokeContinuing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().WetStrokeContinuing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WetStrokeContinuing(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WetStrokeContinuing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WetStrokeContinuing(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_WetStrokeStopping(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WetStrokeStopping, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().WetStrokeStopping(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WetStrokeStopping(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WetStrokeStopping, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WetStrokeStopping(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_WetStrokeCompleted(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WetStrokeCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().WetStrokeCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WetStrokeCompleted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WetStrokeCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WetStrokeCompleted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_WetStrokeCanceled(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WetStrokeCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().WetStrokeCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WetStrokeCanceled(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WetStrokeCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WetStrokeCanceled(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_InkPresenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InkPresenter, WINRT_WRAP(Windows::UI::Input::Inking::InkPresenter));
            *value = detach_from<Windows::UI::Input::Inking::InkPresenter>(this->shim().InkPresenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics> : produce_base<D, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>
{
    int32_t WINRT_CALL Create(void* inkPresenter, void** WetStrokeUpdateSource) noexcept final
    {
        try
        {
            *WetStrokeUpdateSource = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource), Windows::UI::Input::Inking::InkPresenter const&);
            *WetStrokeUpdateSource = detach_from<Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource>(this->shim().Create(*reinterpret_cast<Windows::UI::Input::Inking::InkPresenter const*>(&inkPresenter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Core {

inline CoreIncrementalInkStroke::CoreIncrementalInkStroke(Windows::UI::Input::Inking::InkDrawingAttributes const& drawingAttributes, Windows::Foundation::Numerics::float3x2 const& pointTransform) :
    CoreIncrementalInkStroke(impl::call_factory<CoreIncrementalInkStroke, Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory>([&](auto&& f) { return f.Create(drawingAttributes, pointTransform); }))
{}

inline Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource CoreInkIndependentInputSource::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter)
{
    return impl::call_factory<CoreInkIndependentInputSource, Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics>([&](auto&& f) { return f.Create(inkPresenter); });
}

inline CoreInkPresenterHost::CoreInkPresenterHost() :
    CoreInkPresenterHost(impl::call_factory<CoreInkPresenterHost>([](auto&& f) { return f.template ActivateInstance<CoreInkPresenterHost>(); }))
{}

inline Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource CoreWetStrokeUpdateSource::Create(Windows::UI::Input::Inking::InkPresenter const& inkPresenter)
{
    return impl::call_factory<CoreWetStrokeUpdateSource, Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics>([&](auto&& f) { return f.Create(inkPresenter); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStroke> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreIncrementalInkStrokeFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSource> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreInkIndependentInputSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreInkPresenterHost> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSource> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::ICoreWetStrokeUpdateSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::CoreIncrementalInkStroke> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::CoreInkIndependentInputSource> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::CoreInkPresenterHost> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::CoreInkPresenterHost> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateEventArgs> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Core::CoreWetStrokeUpdateSource> {};

}
