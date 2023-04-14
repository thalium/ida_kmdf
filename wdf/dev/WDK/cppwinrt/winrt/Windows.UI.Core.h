// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::UI::Core::CoreAcceleratorKeyEventType consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::EventType() const
{
    Windows::UI::Core::CoreAcceleratorKeyEventType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAcceleratorKeyEventArgs)->get_EventType(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::VirtualKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAcceleratorKeyEventArgs)->get_VirtualKey(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_UI_Core_IAcceleratorKeyEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAcceleratorKeyEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Core_IAcceleratorKeyEventArgs2<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAcceleratorKeyEventArgs2)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Core_IAutomationProviderRequestedEventArgs<D>::AutomationProvider() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAutomationProviderRequestedEventArgs)->get_AutomationProvider(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_IAutomationProviderRequestedEventArgs<D>::AutomationProvider(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::IAutomationProviderRequestedEventArgs)->put_AutomationProvider(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Core_IBackRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IBackRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_IBackRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::IBackRequestedEventArgs)->put_Handled(value));
}

template <typename D> uint32_t consume_Windows_UI_Core_ICharacterReceivedEventArgs<D>::KeyCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICharacterReceivedEventArgs)->get_KeyCode(&value));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_UI_Core_ICharacterReceivedEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICharacterReceivedEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::PointerPosition() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_PointerPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::SearchBounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_SearchBounds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::ClosestInteractiveBounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->get_ClosestInteractiveBounds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_IClosestInteractiveBoundsRequestedEventArgs<D>::ClosestInteractiveBounds(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs)->put_ClosestInteractiveBounds(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreDispatcher, Windows::UI::Core::AcceleratorKeyEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreAcceleratorKeys)->add_AcceleratorKeyActivated(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated_revoker consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreDispatcher, Windows::UI::Core::AcceleratorKeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AcceleratorKeyActivated_revoker>(this, AcceleratorKeyActivated(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreAcceleratorKeys<D>::AcceleratorKeyActivated(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreAcceleratorKeys)->remove_AcceleratorKeyActivated(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreComponentInputSource, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreClosestInteractiveBoundsRequested)->add_ClosestInteractiveBoundsRequested(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested_revoker consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreComponentInputSource, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ClosestInteractiveBoundsRequested_revoker>(this, ClosestInteractiveBoundsRequested(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreClosestInteractiveBoundsRequested<D>::ClosestInteractiveBoundsRequested(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreClosestInteractiveBoundsRequested)->remove_ClosestInteractiveBoundsRequested(get_abi(cookie)));
}

template <typename D> bool consume_Windows_UI_Core_ICoreComponentFocusable<D>::HasFocus() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreComponentFocusable)->get_HasFocus(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreComponentFocusable)->add_GotFocus(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus_revoker consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreComponentFocusable<D>::GotFocus(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreComponentFocusable)->remove_GotFocus(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreComponentFocusable)->add_LostFocus(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus_revoker consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreComponentFocusable<D>::LostFocus(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreComponentFocusable)->remove_LostFocus(get_abi(cookie)));
}

template <typename D> uint32_t consume_Windows_UI_Core_ICoreCursor<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreCursor)->get_Id(&value));
    return value;
}

template <typename D> Windows::UI::Core::CoreCursorType consume_Windows_UI_Core_ICoreCursor<D>::Type() const
{
    Windows::UI::Core::CoreCursorType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreCursor)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreCursor consume_Windows_UI_Core_ICoreCursorFactory<D>::CreateCursor(Windows::UI::Core::CoreCursorType const& type, uint32_t id) const
{
    Windows::UI::Core::CoreCursor cursor{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreCursorFactory)->CreateCursor(get_abi(type), id, put_abi(cursor)));
    return cursor;
}

template <typename D> bool consume_Windows_UI_Core_ICoreDispatcher<D>::HasThreadAccess() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher)->get_HasThreadAccess(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreDispatcher<D>::ProcessEvents(Windows::UI::Core::CoreProcessEventsOption const& options) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher)->ProcessEvents(get_abi(options)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Core_ICoreDispatcher<D>::RunAsync(Windows::UI::Core::CoreDispatcherPriority const& priority, Windows::UI::Core::DispatchedHandler const& agileCallback) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher)->RunAsync(get_abi(priority), get_abi(agileCallback), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Core_ICoreDispatcher<D>::RunIdleAsync(Windows::UI::Core::IdleDispatchedHandler const& agileCallback) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher)->RunIdleAsync(get_abi(agileCallback), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Core_ICoreDispatcher2<D>::TryRunAsync(Windows::UI::Core::CoreDispatcherPriority const& priority, Windows::UI::Core::DispatchedHandler const& agileCallback) const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher2)->TryRunAsync(get_abi(priority), get_abi(agileCallback), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Core_ICoreDispatcher2<D>::TryRunIdleAsync(Windows::UI::Core::IdleDispatchedHandler const& agileCallback) const
{
    Windows::Foundation::IAsyncOperation<bool> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcher2)->TryRunIdleAsync(get_abi(agileCallback), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::UI::Core::CoreDispatcherPriority consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::CurrentPriority() const
{
    Windows::UI::Core::CoreDispatcherPriority value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcherWithTaskPriority)->get_CurrentPriority(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::CurrentPriority(Windows::UI::Core::CoreDispatcherPriority const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcherWithTaskPriority)->put_CurrentPriority(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::ShouldYield() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcherWithTaskPriority)->ShouldYield(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::ShouldYield(Windows::UI::Core::CoreDispatcherPriority const& priority) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcherWithTaskPriority)->ShouldYieldToPriority(get_abi(priority), &value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreDispatcherWithTaskPriority<D>::StopProcessEvents() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreDispatcherWithTaskPriority)->StopProcessEvents());
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Core_ICoreInputSourceBase<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreInputSourceBase)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Core_ICoreInputSourceBase<D>::IsInputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreInputSourceBase)->get_IsInputEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreInputSourceBase<D>::IsInputEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreInputSourceBase)->put_IsInputEnabled(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::InputEnabledEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreInputSourceBase)->add_InputEnabled(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled_revoker consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::InputEnabledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InputEnabled_revoker>(this, InputEnabled(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreInputSourceBase<D>::InputEnabled(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreInputSourceBase)->remove_InputEnabled(get_abi(cookie)));
}

template <typename D> Windows::UI::Core::CoreVirtualKeyStates consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::GetCurrentKeyState(Windows::System::VirtualKey const& virtualKey) const
{
    Windows::UI::Core::CoreVirtualKeyStates KeyState{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->GetCurrentKeyState(get_abi(virtualKey), put_abi(KeyState)));
    return KeyState;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->add_CharacterReceived(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::CharacterReceived(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->remove_CharacterReceived(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->add_KeyDown(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyDown(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->remove_KeyDown(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->add_KeyUp(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp_revoker consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreKeyboardInputSource<D>::KeyUp(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource)->remove_KeyUp(get_abi(cookie)));
}

template <typename D> hstring consume_Windows_UI_Core_ICoreKeyboardInputSource2<D>::GetCurrentKeyEventDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreKeyboardInputSource2)->GetCurrentKeyEventDeviceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::ReleasePointerCapture() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->ReleasePointerCapture());
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::SetPointerCapture() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->SetPointerCapture());
}

template <typename D> bool consume_Windows_UI_Core_ICorePointerInputSource<D>::HasCapture() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->get_HasCapture(&value));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPosition() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->get_PointerPosition(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreCursor consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCursor() const
{
    Windows::UI::Core::CoreCursor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->get_PointerCursor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCursor(Windows::UI::Core::CoreCursor const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->put_PointerCursor(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerCaptureLost(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerCaptureLost(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerCaptureLost(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerEntered(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerEntered(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerExited(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerExited(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerExited(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerMoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerMoved(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerReleased(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerReleased(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->add_PointerWheelChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged_revoker consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerInputSource<D>::PointerWheelChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource)->remove_PointerWheelChanged(get_abi(cookie)));
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_UI_Core_ICorePointerInputSource2<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerInputSource2)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedAway(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerRoutedAway_revoker>(this, PointerRoutedAway(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedAway(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedAway(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedTo(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerRoutedTo_revoker>(this, PointerRoutedTo(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedTo(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedTo(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->add_PointerRoutedReleased(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased_revoker consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerRoutedReleased_revoker>(this, PointerRoutedReleased(handler));
}

template <typename D> void consume_Windows_UI_Core_ICorePointerRedirector<D>::PointerRoutedReleased(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICorePointerRedirector)->remove_PointerRoutedReleased(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreTouchHitTesting)->add_TouchHitTesting(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting_revoker consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TouchHitTesting_revoker>(this, TouchHitTesting(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreTouchHitTesting<D>::TouchHitTesting(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreTouchHitTesting)->remove_TouchHitTesting(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Core_ICoreWindow<D>::AutomationHostProvider() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_AutomationHostProvider(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Core_ICoreWindow<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_UI_Core_ICoreWindow<D>::CustomProperties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_CustomProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Core_ICoreWindow<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreWindowFlowDirection consume_Windows_UI_Core_ICoreWindow<D>::FlowDirection() const
{
    Windows::UI::Core::CoreWindowFlowDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_FlowDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::FlowDirection(Windows::UI::Core::CoreWindowFlowDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->put_FlowDirection(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Core_ICoreWindow<D>::IsInputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_IsInputEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::IsInputEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->put_IsInputEnabled(value));
}

template <typename D> Windows::UI::Core::CoreCursor consume_Windows_UI_Core_ICoreWindow<D>::PointerCursor() const
{
    Windows::UI::Core::CoreCursor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_PointerCursor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerCursor(Windows::UI::Core::CoreCursor const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->put_PointerCursor(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_ICoreWindow<D>::PointerPosition() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_PointerPosition(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Core_ICoreWindow<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::Activate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->Activate());
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->Close());
}

template <typename D> Windows::UI::Core::CoreVirtualKeyStates consume_Windows_UI_Core_ICoreWindow<D>::GetAsyncKeyState(Windows::System::VirtualKey const& virtualKey) const
{
    Windows::UI::Core::CoreVirtualKeyStates KeyState{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->GetAsyncKeyState(get_abi(virtualKey), put_abi(KeyState)));
    return KeyState;
}

template <typename D> Windows::UI::Core::CoreVirtualKeyStates consume_Windows_UI_Core_ICoreWindow<D>::GetKeyState(Windows::System::VirtualKey const& virtualKey) const
{
    Windows::UI::Core::CoreVirtualKeyStates KeyState{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->GetKeyState(get_abi(virtualKey), put_abi(KeyState)));
    return KeyState;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::ReleasePointerCapture() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->ReleasePointerCapture());
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::SetPointerCapture() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->SetPointerCapture());
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::Activated(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowActivatedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_Activated(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::Activated_revoker consume_Windows_UI_Core_ICoreWindow<D>::Activated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowActivatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::Activated(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_Activated(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::AutomationProviderRequestedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_AutomationProviderRequested(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested_revoker consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::AutomationProviderRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AutomationProviderRequested_revoker>(this, AutomationProviderRequested(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::AutomationProviderRequested(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_AutomationProviderRequested(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_CharacterReceived(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived_revoker consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CharacterReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::CharacterReceived(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_CharacterReceived(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_Closed(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::Closed_revoker consume_Windows_UI_Core_ICoreWindow<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::Closed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_Closed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::InputEnabledEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_InputEnabled(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled_revoker consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::InputEnabledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, InputEnabled_revoker>(this, InputEnabled(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::InputEnabled(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_InputEnabled(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_KeyDown(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::KeyDown_revoker consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::KeyDown(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_KeyDown(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_KeyUp(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::KeyUp_revoker consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::KeyUp(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_KeyUp(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerCaptureLost(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerCaptureLost(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerCaptureLost(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerEntered(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerEntered(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerEntered(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerExited(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerExited_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerExited(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerExited(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerMoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerMoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerMoved(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerPressed(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerPressed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerPressed(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerReleased(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerReleased(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerReleased(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_TouchHitTesting(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting_revoker consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::TouchHitTestingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TouchHitTesting_revoker>(this, TouchHitTesting(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::TouchHitTesting(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_TouchHitTesting(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_PointerWheelChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::PointerWheelChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_PointerWheelChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowSizeChangedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_SizeChanged(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowSizeChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::SizeChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_SizeChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::VisibilityChangedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow)->add_VisibilityChanged(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged_revoker consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::VisibilityChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow<D>::VisibilityChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow)->remove_VisibilityChanged(get_abi(cookie)));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow2<D>::PointerPosition(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow2)->put_PointerPosition(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow3)->add_ClosestInteractiveBoundsRequested(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested_revoker consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ClosestInteractiveBoundsRequested_revoker>(this, ClosestInteractiveBoundsRequested(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow3<D>::ClosestInteractiveBoundsRequested(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow3)->remove_ClosestInteractiveBoundsRequested(get_abi(cookie)));
}

template <typename D> hstring consume_Windows_UI_Core_ICoreWindow3<D>::GetCurrentKeyEventDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow3)->GetCurrentKeyEventDeviceId(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow4)->add_ResizeStarted(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted_revoker consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ResizeStarted_revoker>(this, ResizeStarted(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow4<D>::ResizeStarted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow4)->remove_ResizeStarted(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token pCookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow4)->add_ResizeCompleted(get_abi(handler), put_abi(pCookie)));
    return pCookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted_revoker consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ResizeCompleted_revoker>(this, ResizeCompleted(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindow4<D>::ResizeCompleted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindow4)->remove_ResizeCompleted(get_abi(cookie)));
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_UI_Core_ICoreWindow5<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow5)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreWindowActivationMode consume_Windows_UI_Core_ICoreWindow5<D>::ActivationMode() const
{
    Windows::UI::Core::CoreWindowActivationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindow5)->get_ActivationMode(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->add_Showing(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing_revoker consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Showing_revoker>(this, Showing(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::Showing(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->remove_Showing(get_abi(cookie)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Core_ICoreWindowDialog<D>::MaxSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_MaxSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Core_ICoreWindowDialog<D>::MinSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_MinSize(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Core_ICoreWindowDialog<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->put_Title(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Core_ICoreWindowDialog<D>::IsInteractionDelayed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_IsInteractionDelayed(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::IsInteractionDelayed(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->put_IsInteractionDelayed(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> consume_Windows_UI_Core_ICoreWindowDialog<D>::Commands() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_Commands(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Core_ICoreWindowDialog<D>::DefaultCommandIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_DefaultCommandIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::DefaultCommandIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->put_DefaultCommandIndex(value));
}

template <typename D> uint32_t consume_Windows_UI_Core_ICoreWindowDialog<D>::CancelCommandIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_CancelCommandIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::CancelCommandIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->put_CancelCommandIndex(value));
}

template <typename D> Windows::UI::Popups::UICommandInvokedHandler consume_Windows_UI_Core_ICoreWindowDialog<D>::BackButtonCommand() const
{
    Windows::UI::Popups::UICommandInvokedHandler value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->get_BackButtonCommand(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowDialog<D>::BackButtonCommand(Windows::UI::Popups::UICommandInvokedHandler const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->put_BackButtonCommand(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Core_ICoreWindowDialog<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialog)->ShowAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::UI::Core::CoreWindowDialog consume_Windows_UI_Core_ICoreWindowDialogFactory<D>::CreateWithTitle(param::hstring const& title) const
{
    Windows::UI::Core::CoreWindowDialog coreWindowDialog{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowDialogFactory)->CreateWithTitle(get_abi(title), put_abi(coreWindowDialog)));
    return coreWindowDialog;
}

template <typename D> bool consume_Windows_UI_Core_ICoreWindowEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowEventArgs)->put_Handled(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->add_Showing(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing_revoker consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Showing_revoker>(this, Showing(handler));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowFlyout<D>::Showing(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->remove_Showing(get_abi(cookie)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Core_ICoreWindowFlyout<D>::MaxSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_MaxSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Core_ICoreWindowFlyout<D>::MinSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_MinSize(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Core_ICoreWindowFlyout<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowFlyout<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->put_Title(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Core_ICoreWindowFlyout<D>::IsInteractionDelayed() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_IsInteractionDelayed(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowFlyout<D>::IsInteractionDelayed(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->put_IsInteractionDelayed(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> consume_Windows_UI_Core_ICoreWindowFlyout<D>::Commands() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_Commands(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Core_ICoreWindowFlyout<D>::DefaultCommandIndex() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_DefaultCommandIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowFlyout<D>::DefaultCommandIndex(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->put_DefaultCommandIndex(value));
}

template <typename D> Windows::UI::Popups::UICommandInvokedHandler consume_Windows_UI_Core_ICoreWindowFlyout<D>::BackButtonCommand() const
{
    Windows::UI::Popups::UICommandInvokedHandler value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->get_BackButtonCommand(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowFlyout<D>::BackButtonCommand(Windows::UI::Popups::UICommandInvokedHandler const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->put_BackButtonCommand(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> consume_Windows_UI_Core_ICoreWindowFlyout<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyout)->ShowAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::UI::Core::CoreWindowFlyout consume_Windows_UI_Core_ICoreWindowFlyoutFactory<D>::Create(Windows::Foundation::Point const& position) const
{
    Windows::UI::Core::CoreWindowFlyout coreWindowFlyout{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyoutFactory)->Create(get_abi(position), put_abi(coreWindowFlyout)));
    return coreWindowFlyout;
}

template <typename D> Windows::UI::Core::CoreWindowFlyout consume_Windows_UI_Core_ICoreWindowFlyoutFactory<D>::CreateWithTitle(Windows::Foundation::Point const& position, param::hstring const& title) const
{
    Windows::UI::Core::CoreWindowFlyout coreWindowFlyout{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowFlyoutFactory)->CreateWithTitle(get_abi(position), get_abi(title), put_abi(coreWindowFlyout)));
    return coreWindowFlyout;
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowPopupShowingEventArgs<D>::SetDesiredSize(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowPopupShowingEventArgs)->SetDesiredSize(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowResizeManager<D>::NotifyLayoutCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowResizeManager)->NotifyLayoutCompleted());
}

template <typename D> void consume_Windows_UI_Core_ICoreWindowResizeManagerLayoutCapability<D>::ShouldWaitForLayoutCompletion(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability)->put_ShouldWaitForLayoutCompletion(value));
}

template <typename D> bool consume_Windows_UI_Core_ICoreWindowResizeManagerLayoutCapability<D>::ShouldWaitForLayoutCompletion() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability)->get_ShouldWaitForLayoutCompletion(&value));
    return value;
}

template <typename D> Windows::UI::Core::CoreWindowResizeManager consume_Windows_UI_Core_ICoreWindowResizeManagerStatics<D>::GetForCurrentView() const
{
    Windows::UI::Core::CoreWindowResizeManager CoreWindowResizeManager{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowResizeManagerStatics)->GetForCurrentView(put_abi(CoreWindowResizeManager)));
    return CoreWindowResizeManager;
}

template <typename D> Windows::UI::Core::CoreWindow consume_Windows_UI_Core_ICoreWindowStatic<D>::GetForCurrentThread() const
{
    Windows::UI::Core::CoreWindow ppWindow{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowStatic)->GetForCurrentThread(put_abi(ppWindow)));
    return ppWindow;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_Core_ICoreWindowWithContext<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ICoreWindowWithContext)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Core_IIdleDispatchedHandlerArgs<D>::IsDispatcherIdle() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IIdleDispatchedHandlerArgs)->get_IsDispatcherIdle(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_IInitializeWithCoreWindow<D>::Initialize(Windows::UI::Core::CoreWindow const& window) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::IInitializeWithCoreWindow)->Initialize(get_abi(window)));
}

template <typename D> bool consume_Windows_UI_Core_IInputEnabledEventArgs<D>::InputEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IInputEnabledEventArgs)->get_InputEnabled(&value));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Core_IKeyEventArgs<D>::VirtualKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IKeyEventArgs)->get_VirtualKey(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_UI_Core_IKeyEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IKeyEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Core_IKeyEventArgs2<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IKeyEventArgs2)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::PointerPoint consume_Windows_UI_Core_IPointerEventArgs<D>::CurrentPoint() const
{
    Windows::UI::Input::PointerPoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::IPointerEventArgs)->get_CurrentPoint(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_UI_Core_IPointerEventArgs<D>::KeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IPointerEventArgs)->get_KeyModifiers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> consume_Windows_UI_Core_IPointerEventArgs<D>::GetIntermediatePoints() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::IPointerEventArgs)->GetIntermediatePoints(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(Windows::Foundation::EventHandler<Windows::UI::Core::BackRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ISystemNavigationManager)->add_BackRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested_revoker consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Core::BackRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BackRequested_revoker>(this, BackRequested(handler));
}

template <typename D> void consume_Windows_UI_Core_ISystemNavigationManager<D>::BackRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::ISystemNavigationManager)->remove_BackRequested(get_abi(token)));
}

template <typename D> Windows::UI::Core::AppViewBackButtonVisibility consume_Windows_UI_Core_ISystemNavigationManager2<D>::AppViewBackButtonVisibility() const
{
    Windows::UI::Core::AppViewBackButtonVisibility value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ISystemNavigationManager2)->get_AppViewBackButtonVisibility(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ISystemNavigationManager2<D>::AppViewBackButtonVisibility(Windows::UI::Core::AppViewBackButtonVisibility const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ISystemNavigationManager2)->put_AppViewBackButtonVisibility(get_abi(value)));
}

template <typename D> Windows::UI::Core::SystemNavigationManager consume_Windows_UI_Core_ISystemNavigationManagerStatics<D>::GetForCurrentView() const
{
    Windows::UI::Core::SystemNavigationManager loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::ISystemNavigationManagerStatics)->GetForCurrentView(put_abi(loader)));
    return loader;
}

template <typename D> Windows::UI::Core::CoreProximityEvaluation consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::ProximityEvaluation() const
{
    Windows::UI::Core::CoreProximityEvaluation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->get_ProximityEvaluation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::ProximityEvaluation(Windows::UI::Core::CoreProximityEvaluation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->put_ProximityEvaluation(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::Point() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->get_Point(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::BoundingBox() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreProximityEvaluation consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::EvaluateProximity(Windows::Foundation::Rect const& controlBoundingBox) const
{
    Windows::UI::Core::CoreProximityEvaluation proximityEvaluation{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->EvaluateProximityToRect(get_abi(controlBoundingBox), put_abi(proximityEvaluation)));
    return proximityEvaluation;
}

template <typename D> Windows::UI::Core::CoreProximityEvaluation consume_Windows_UI_Core_ITouchHitTestingEventArgs<D>::EvaluateProximity(array_view<Windows::Foundation::Point const> controlVertices) const
{
    Windows::UI::Core::CoreProximityEvaluation proximityEvaluation{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::ITouchHitTestingEventArgs)->EvaluateProximityToPolygon(controlVertices.size(), get_abi(controlVertices), put_abi(proximityEvaluation)));
    return proximityEvaluation;
}

template <typename D> bool consume_Windows_UI_Core_IVisibilityChangedEventArgs<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IVisibilityChangedEventArgs)->get_Visible(&value));
    return value;
}

template <typename D> Windows::UI::Core::CoreWindowActivationState consume_Windows_UI_Core_IWindowActivatedEventArgs<D>::WindowActivationState() const
{
    Windows::UI::Core::CoreWindowActivationState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IWindowActivatedEventArgs)->get_WindowActivationState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Core_IWindowSizeChangedEventArgs<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::IWindowSizeChangedEventArgs)->get_Size(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::UI::Core::DispatchedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Core::DispatchedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Core::DispatchedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Core::IdleDispatchedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Core::IdleDispatchedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Core::IdleDispatchedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::Core::IdleDispatchedHandlerArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::UI::Core::IAcceleratorKeyEventArgs> : produce_base<D, Windows::UI::Core::IAcceleratorKeyEventArgs>
{
    int32_t WINRT_CALL get_EventType(Windows::UI::Core::CoreAcceleratorKeyEventType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventType, WINRT_WRAP(Windows::UI::Core::CoreAcceleratorKeyEventType));
            *value = detach_from<Windows::UI::Core::CoreAcceleratorKeyEventType>(this->shim().EventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VirtualKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyStatus, WINRT_WRAP(Windows::UI::Core::CorePhysicalKeyStatus));
            *value = detach_from<Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IAcceleratorKeyEventArgs2> : produce_base<D, Windows::UI::Core::IAcceleratorKeyEventArgs2>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IAutomationProviderRequestedEventArgs> : produce_base<D, Windows::UI::Core::IAutomationProviderRequestedEventArgs>
{
    int32_t WINRT_CALL get_AutomationProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationProvider, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().AutomationProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutomationProvider(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationProvider, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().AutomationProvider(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IBackRequestedEventArgs> : produce_base<D, Windows::UI::Core::IBackRequestedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICharacterReceivedEventArgs> : produce_base<D, Windows::UI::Core::ICharacterReceivedEventArgs>
{
    int32_t WINRT_CALL get_KeyCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().KeyCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyStatus, WINRT_WRAP(Windows::UI::Core::CorePhysicalKeyStatus));
            *value = detach_from<Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs> : produce_base<D, Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs>
{
    int32_t WINRT_CALL get_PointerPosition(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPosition, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchBounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchBounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().SearchBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClosestInteractiveBounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosestInteractiveBounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ClosestInteractiveBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClosestInteractiveBounds(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosestInteractiveBounds, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().ClosestInteractiveBounds(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreAcceleratorKeys> : produce_base<D, Windows::UI::Core::ICoreAcceleratorKeys>
{
    int32_t WINRT_CALL add_AcceleratorKeyActivated(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceleratorKeyActivated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreDispatcher, Windows::UI::Core::AcceleratorKeyEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().AcceleratorKeyActivated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreDispatcher, Windows::UI::Core::AcceleratorKeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AcceleratorKeyActivated(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AcceleratorKeyActivated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AcceleratorKeyActivated(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreClosestInteractiveBoundsRequested> : produce_base<D, Windows::UI::Core::ICoreClosestInteractiveBoundsRequested>
{
    int32_t WINRT_CALL add_ClosestInteractiveBoundsRequested(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosestInteractiveBoundsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreComponentInputSource, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreComponentInputSource, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ClosestInteractiveBoundsRequested(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ClosestInteractiveBoundsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreComponentFocusable> : produce_base<D, Windows::UI::Core::ICoreComponentFocusable>
{
    int32_t WINRT_CALL get_HasFocus(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasFocus, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreCursor> : produce_base<D, Windows::UI::Core::ICoreCursor>
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

    int32_t WINRT_CALL get_Type(Windows::UI::Core::CoreCursorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Core::CoreCursorType));
            *value = detach_from<Windows::UI::Core::CoreCursorType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreCursorFactory> : produce_base<D, Windows::UI::Core::ICoreCursorFactory>
{
    int32_t WINRT_CALL CreateCursor(Windows::UI::Core::CoreCursorType type, uint32_t id, void** cursor) noexcept final
    {
        try
        {
            *cursor = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCursor, WINRT_WRAP(Windows::UI::Core::CoreCursor), Windows::UI::Core::CoreCursorType const&, uint32_t);
            *cursor = detach_from<Windows::UI::Core::CoreCursor>(this->shim().CreateCursor(*reinterpret_cast<Windows::UI::Core::CoreCursorType const*>(&type), id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreDispatcher> : produce_base<D, Windows::UI::Core::ICoreDispatcher>
{
    int32_t WINRT_CALL get_HasThreadAccess(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasThreadAccess, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasThreadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessEvents(Windows::UI::Core::CoreProcessEventsOption options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessEvents, WINRT_WRAP(void), Windows::UI::Core::CoreProcessEventsOption const&);
            this->shim().ProcessEvents(*reinterpret_cast<Windows::UI::Core::CoreProcessEventsOption const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunAsync(Windows::UI::Core::CoreDispatcherPriority priority, void* agileCallback, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Core::CoreDispatcherPriority const, Windows::UI::Core::DispatchedHandler const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunAsync(*reinterpret_cast<Windows::UI::Core::CoreDispatcherPriority const*>(&priority), *reinterpret_cast<Windows::UI::Core::DispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunIdleAsync(void* agileCallback, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunIdleAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Core::IdleDispatchedHandler const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RunIdleAsync(*reinterpret_cast<Windows::UI::Core::IdleDispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreDispatcher2> : produce_base<D, Windows::UI::Core::ICoreDispatcher2>
{
    int32_t WINRT_CALL TryRunAsync(Windows::UI::Core::CoreDispatcherPriority priority, void* agileCallback, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRunAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::Core::CoreDispatcherPriority const, Windows::UI::Core::DispatchedHandler const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRunAsync(*reinterpret_cast<Windows::UI::Core::CoreDispatcherPriority const*>(&priority), *reinterpret_cast<Windows::UI::Core::DispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRunIdleAsync(void* agileCallback, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRunIdleAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::Core::IdleDispatchedHandler const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRunIdleAsync(*reinterpret_cast<Windows::UI::Core::IdleDispatchedHandler const*>(&agileCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreDispatcherWithTaskPriority> : produce_base<D, Windows::UI::Core::ICoreDispatcherWithTaskPriority>
{
    int32_t WINRT_CALL get_CurrentPriority(Windows::UI::Core::CoreDispatcherPriority* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPriority, WINRT_WRAP(Windows::UI::Core::CoreDispatcherPriority));
            *value = detach_from<Windows::UI::Core::CoreDispatcherPriority>(this->shim().CurrentPriority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CurrentPriority(Windows::UI::Core::CoreDispatcherPriority value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPriority, WINRT_WRAP(void), Windows::UI::Core::CoreDispatcherPriority const&);
            this->shim().CurrentPriority(*reinterpret_cast<Windows::UI::Core::CoreDispatcherPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShouldYield(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldYield, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldYield());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShouldYieldToPriority(Windows::UI::Core::CoreDispatcherPriority priority, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldYield, WINRT_WRAP(bool), Windows::UI::Core::CoreDispatcherPriority const&);
            *value = detach_from<bool>(this->shim().ShouldYield(*reinterpret_cast<Windows::UI::Core::CoreDispatcherPriority const*>(&priority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopProcessEvents() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopProcessEvents, WINRT_WRAP(void));
            this->shim().StopProcessEvents();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreInputSourceBase> : produce_base<D, Windows::UI::Core::ICoreInputSourceBase>
{
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

    int32_t WINRT_CALL get_IsInputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInputEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(void), bool);
            this->shim().IsInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_InputEnabled(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputEnabled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::InputEnabledEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().InputEnabled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::InputEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InputEnabled(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InputEnabled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InputEnabled(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreKeyboardInputSource> : produce_base<D, Windows::UI::Core::ICoreKeyboardInputSource>
{
    int32_t WINRT_CALL GetCurrentKeyState(Windows::System::VirtualKey virtualKey, Windows::UI::Core::CoreVirtualKeyStates* KeyState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentKeyState, WINRT_WRAP(Windows::UI::Core::CoreVirtualKeyStates), Windows::System::VirtualKey const&);
            *KeyState = detach_from<Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetCurrentKeyState(*reinterpret_cast<Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CharacterReceived(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CharacterReceivedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::CharacterReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CharacterReceived(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_KeyDown(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyDown(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_KeyUp(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyUp(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreKeyboardInputSource2> : produce_base<D, Windows::UI::Core::ICoreKeyboardInputSource2>
{
    int32_t WINRT_CALL GetCurrentKeyEventDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentKeyEventDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetCurrentKeyEventDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICorePointerInputSource> : produce_base<D, Windows::UI::Core::ICorePointerInputSource>
{
    int32_t WINRT_CALL ReleasePointerCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleasePointerCapture, WINRT_WRAP(void));
            this->shim().ReleasePointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPointerCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPointerCapture, WINRT_WRAP(void));
            this->shim().SetPointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasCapture(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasCapture, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerPosition(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPosition, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCursor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCursor, WINRT_WRAP(Windows::UI::Core::CoreCursor));
            *value = detach_from<Windows::UI::Core::CoreCursor>(this->shim().PointerCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerCursor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCursor, WINRT_WRAP(void), Windows::UI::Core::CoreCursor const&);
            this->shim().PointerCursor(*reinterpret_cast<Windows::UI::Core::CoreCursor const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PointerCaptureLost(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerCaptureLost(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerEntered(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerExited(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerMoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerReleased(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerWheelChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerWheelChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICorePointerInputSource2> : produce_base<D, Windows::UI::Core::ICorePointerInputSource2>
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
struct produce<D, Windows::UI::Core::ICorePointerRedirector> : produce_base<D, Windows::UI::Core::ICorePointerRedirector>
{
    int32_t WINRT_CALL add_PointerRoutedAway(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerRoutedAway, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedAway(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerRoutedAway(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerRoutedAway, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerRoutedAway(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerRoutedTo(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerRoutedTo, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedTo(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerRoutedTo(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerRoutedTo, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerRoutedTo(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerRoutedReleased(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerRoutedReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerRoutedReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::ICorePointerRedirector, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerRoutedReleased(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerRoutedReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerRoutedReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreTouchHitTesting> : produce_base<D, Windows::UI::Core::ICoreTouchHitTesting>
{
    int32_t WINRT_CALL add_TouchHitTesting(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchHitTesting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::TouchHitTestingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().TouchHitTesting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::UI::Core::TouchHitTestingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TouchHitTesting(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TouchHitTesting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TouchHitTesting(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindow> : produce_base<D, Windows::UI::Core::ICoreWindow>
{
    int32_t WINRT_CALL get_AutomationHostProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationHostProvider, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().AutomationHostProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_CustomProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomProperties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().CustomProperties());
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

    int32_t WINRT_CALL get_FlowDirection(Windows::UI::Core::CoreWindowFlowDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(Windows::UI::Core::CoreWindowFlowDirection));
            *value = detach_from<Windows::UI::Core::CoreWindowFlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FlowDirection(Windows::UI::Core::CoreWindowFlowDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(void), Windows::UI::Core::CoreWindowFlowDirection const&);
            this->shim().FlowDirection(*reinterpret_cast<Windows::UI::Core::CoreWindowFlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInputEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInputEnabled, WINRT_WRAP(void), bool);
            this->shim().IsInputEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCursor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCursor, WINRT_WRAP(Windows::UI::Core::CoreCursor));
            *value = detach_from<Windows::UI::Core::CoreCursor>(this->shim().PointerCursor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PointerCursor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCursor, WINRT_WRAP(void), Windows::UI::Core::CoreCursor const&);
            this->shim().PointerCursor(*reinterpret_cast<Windows::UI::Core::CoreCursor const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerPosition(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPosition, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().PointerPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Activate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activate, WINRT_WRAP(void));
            this->shim().Activate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAsyncKeyState(Windows::System::VirtualKey virtualKey, Windows::UI::Core::CoreVirtualKeyStates* KeyState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsyncKeyState, WINRT_WRAP(Windows::UI::Core::CoreVirtualKeyStates), Windows::System::VirtualKey const&);
            *KeyState = detach_from<Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetAsyncKeyState(*reinterpret_cast<Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetKeyState(Windows::System::VirtualKey virtualKey, Windows::UI::Core::CoreVirtualKeyStates* KeyState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetKeyState, WINRT_WRAP(Windows::UI::Core::CoreVirtualKeyStates), Windows::System::VirtualKey const&);
            *KeyState = detach_from<Windows::UI::Core::CoreVirtualKeyStates>(this->shim().GetKeyState(*reinterpret_cast<Windows::System::VirtualKey const*>(&virtualKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReleasePointerCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleasePointerCapture, WINRT_WRAP(void));
            this->shim().ReleasePointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPointerCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPointerCapture, WINRT_WRAP(void));
            this->shim().SetPointerCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowActivatedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowActivatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Activated(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_AutomationProviderRequested(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationProviderRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::AutomationProviderRequestedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AutomationProviderRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::AutomationProviderRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AutomationProviderRequested(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AutomationProviderRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AutomationProviderRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_CharacterReceived(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CharacterReceivedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CharacterReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CharacterReceived(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_InputEnabled(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputEnabled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::InputEnabledEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().InputEnabled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::InputEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_InputEnabled(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(InputEnabled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().InputEnabled(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_KeyDown(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyDown(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_KeyUp(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::KeyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyUp(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerCaptureLost(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerCaptureLost(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerEntered(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerEntered(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerExited(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerExited(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerMoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerMoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerPressed(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerPressed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerReleased(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerReleased(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_TouchHitTesting(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchHitTesting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::TouchHitTestingEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().TouchHitTesting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::TouchHitTestingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TouchHitTesting(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TouchHitTesting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TouchHitTesting(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PointerWheelChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::PointerEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerWheelChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_SizeChanged(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowSizeChangedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::WindowSizeChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SizeChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_VisibilityChanged(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::VisibilityChangedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::VisibilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisibilityChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindow2> : produce_base<D, Windows::UI::Core::ICoreWindow2>
{
    int32_t WINRT_CALL put_PointerPosition(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPosition, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().PointerPosition(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindow3> : produce_base<D, Windows::UI::Core::ICoreWindow3>
{
    int32_t WINRT_CALL add_ClosestInteractiveBoundsRequested(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClosestInteractiveBoundsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ClosestInteractiveBoundsRequested(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ClosestInteractiveBoundsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ClosestInteractiveBoundsRequested(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL GetCurrentKeyEventDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentKeyEventDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetCurrentKeyEventDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindow4> : produce_base<D, Windows::UI::Core::ICoreWindow4>
{
    int32_t WINRT_CALL add_ResizeStarted(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResizeStarted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ResizeStarted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResizeStarted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResizeStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResizeStarted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_ResizeCompleted(void* handler, winrt::event_token* pCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResizeCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const&);
            *pCookie = detach_from<winrt::event_token>(this->shim().ResizeCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResizeCompleted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResizeCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResizeCompleted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindow5> : produce_base<D, Windows::UI::Core::ICoreWindow5>
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

    int32_t WINRT_CALL get_ActivationMode(Windows::UI::Core::CoreWindowActivationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationMode, WINRT_WRAP(Windows::UI::Core::CoreWindowActivationMode));
            *value = detach_from<Windows::UI::Core::CoreWindowActivationMode>(this->shim().ActivationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowDialog> : produce_base<D, Windows::UI::Core::ICoreWindowDialog>
{
    int32_t WINRT_CALL add_Showing(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Showing(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_MaxSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MaxSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MinSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInteractionDelayed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInteractionDelayed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().IsInteractionDelayed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInteractionDelayed(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInteractionDelayed, WINRT_WRAP(void), int32_t);
            this->shim().IsInteractionDelayed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Commands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commands, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultCommandIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DefaultCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultCommandIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(void), uint32_t);
            this->shim().DefaultCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CancelCommandIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelCommandIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CancelCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CancelCommandIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelCommandIndex, WINRT_WRAP(void), uint32_t);
            this->shim().CancelCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackButtonCommand(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackButtonCommand, WINRT_WRAP(Windows::UI::Popups::UICommandInvokedHandler));
            *value = detach_from<Windows::UI::Popups::UICommandInvokedHandler>(this->shim().BackButtonCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackButtonCommand(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackButtonCommand, WINRT_WRAP(void), Windows::UI::Popups::UICommandInvokedHandler const&);
            this->shim().BackButtonCommand(*reinterpret_cast<Windows::UI::Popups::UICommandInvokedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowDialogFactory> : produce_base<D, Windows::UI::Core::ICoreWindowDialogFactory>
{
    int32_t WINRT_CALL CreateWithTitle(void* title, void** coreWindowDialog) noexcept final
    {
        try
        {
            *coreWindowDialog = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTitle, WINRT_WRAP(Windows::UI::Core::CoreWindowDialog), hstring const&);
            *coreWindowDialog = detach_from<Windows::UI::Core::CoreWindowDialog>(this->shim().CreateWithTitle(*reinterpret_cast<hstring const*>(&title)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowEventArgs> : produce_base<D, Windows::UI::Core::ICoreWindowEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowFlyout> : produce_base<D, Windows::UI::Core::ICoreWindowFlyout>
{
    int32_t WINRT_CALL add_Showing(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Core::CoreWindow, Windows::UI::Core::CoreWindowPopupShowingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Showing(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL get_MaxSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MaxSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().MinSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInteractionDelayed(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInteractionDelayed, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().IsInteractionDelayed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInteractionDelayed(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInteractionDelayed, WINRT_WRAP(void), int32_t);
            this->shim().IsInteractionDelayed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Commands(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commands, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Popups::IUICommand>>(this->shim().Commands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultCommandIndex(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DefaultCommandIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultCommandIndex(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultCommandIndex, WINRT_WRAP(void), uint32_t);
            this->shim().DefaultCommandIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackButtonCommand(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackButtonCommand, WINRT_WRAP(Windows::UI::Popups::UICommandInvokedHandler));
            *value = detach_from<Windows::UI::Popups::UICommandInvokedHandler>(this->shim().BackButtonCommand());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackButtonCommand(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackButtonCommand, WINRT_WRAP(void), Windows::UI::Popups::UICommandInvokedHandler const&);
            this->shim().BackButtonCommand(*reinterpret_cast<Windows::UI::Popups::UICommandInvokedHandler const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Popups::IUICommand>>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowFlyoutFactory> : produce_base<D, Windows::UI::Core::ICoreWindowFlyoutFactory>
{
    int32_t WINRT_CALL Create(Windows::Foundation::Point position, void** coreWindowFlyout) noexcept final
    {
        try
        {
            *coreWindowFlyout = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Core::CoreWindowFlyout), Windows::Foundation::Point const&);
            *coreWindowFlyout = detach_from<Windows::UI::Core::CoreWindowFlyout>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Point const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTitle(Windows::Foundation::Point position, void* title, void** coreWindowFlyout) noexcept final
    {
        try
        {
            *coreWindowFlyout = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTitle, WINRT_WRAP(Windows::UI::Core::CoreWindowFlyout), Windows::Foundation::Point const&, hstring const&);
            *coreWindowFlyout = detach_from<Windows::UI::Core::CoreWindowFlyout>(this->shim().CreateWithTitle(*reinterpret_cast<Windows::Foundation::Point const*>(&position), *reinterpret_cast<hstring const*>(&title)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowPopupShowingEventArgs> : produce_base<D, Windows::UI::Core::ICoreWindowPopupShowingEventArgs>
{
    int32_t WINRT_CALL SetDesiredSize(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDesiredSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().SetDesiredSize(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowResizeManager> : produce_base<D, Windows::UI::Core::ICoreWindowResizeManager>
{
    int32_t WINRT_CALL NotifyLayoutCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyLayoutCompleted, WINRT_WRAP(void));
            this->shim().NotifyLayoutCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability> : produce_base<D, Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability>
{
    int32_t WINRT_CALL put_ShouldWaitForLayoutCompletion(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldWaitForLayoutCompletion, WINRT_WRAP(void), bool);
            this->shim().ShouldWaitForLayoutCompletion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldWaitForLayoutCompletion(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldWaitForLayoutCompletion, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldWaitForLayoutCompletion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowResizeManagerStatics> : produce_base<D, Windows::UI::Core::ICoreWindowResizeManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** CoreWindowResizeManager) noexcept final
    {
        try
        {
            *CoreWindowResizeManager = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Core::CoreWindowResizeManager));
            *CoreWindowResizeManager = detach_from<Windows::UI::Core::CoreWindowResizeManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowStatic> : produce_base<D, Windows::UI::Core::ICoreWindowStatic>
{
    int32_t WINRT_CALL GetForCurrentThread(void** ppWindow) noexcept final
    {
        try
        {
            *ppWindow = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentThread, WINRT_WRAP(Windows::UI::Core::CoreWindow));
            *ppWindow = detach_from<Windows::UI::Core::CoreWindow>(this->shim().GetForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ICoreWindowWithContext> : produce_base<D, Windows::UI::Core::ICoreWindowWithContext>
{
    int32_t WINRT_CALL get_UIContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIContext, WINRT_WRAP(Windows::UI::UIContext));
            *value = detach_from<Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IIdleDispatchedHandlerArgs> : produce_base<D, Windows::UI::Core::IIdleDispatchedHandlerArgs>
{
    int32_t WINRT_CALL get_IsDispatcherIdle(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDispatcherIdle, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDispatcherIdle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IInitializeWithCoreWindow> : produce_base<D, Windows::UI::Core::IInitializeWithCoreWindow>
{
    int32_t WINRT_CALL Initialize(void* window) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Initialize, WINRT_WRAP(void), Windows::UI::Core::CoreWindow const&);
            this->shim().Initialize(*reinterpret_cast<Windows::UI::Core::CoreWindow const*>(&window));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IInputEnabledEventArgs> : produce_base<D, Windows::UI::Core::IInputEnabledEventArgs>
{
    int32_t WINRT_CALL get_InputEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InputEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IKeyEventArgs> : produce_base<D, Windows::UI::Core::IKeyEventArgs>
{
    int32_t WINRT_CALL get_VirtualKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyStatus, WINRT_WRAP(Windows::UI::Core::CorePhysicalKeyStatus));
            *value = detach_from<Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IKeyEventArgs2> : produce_base<D, Windows::UI::Core::IKeyEventArgs2>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IPointerEventArgs> : produce_base<D, Windows::UI::Core::IPointerEventArgs>
{
    int32_t WINRT_CALL get_CurrentPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPoint, WINRT_WRAP(Windows::UI::Input::PointerPoint));
            *value = detach_from<Windows::UI::Input::PointerPoint>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().KeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIntermediatePoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIntermediatePoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ISystemNavigationManager> : produce_base<D, Windows::UI::Core::ISystemNavigationManager>
{
    int32_t WINRT_CALL add_BackRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Core::BackRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BackRequested(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Core::BackRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BackRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BackRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BackRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ISystemNavigationManager2> : produce_base<D, Windows::UI::Core::ISystemNavigationManager2>
{
    int32_t WINRT_CALL get_AppViewBackButtonVisibility(Windows::UI::Core::AppViewBackButtonVisibility* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppViewBackButtonVisibility, WINRT_WRAP(Windows::UI::Core::AppViewBackButtonVisibility));
            *value = detach_from<Windows::UI::Core::AppViewBackButtonVisibility>(this->shim().AppViewBackButtonVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppViewBackButtonVisibility(Windows::UI::Core::AppViewBackButtonVisibility value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppViewBackButtonVisibility, WINRT_WRAP(void), Windows::UI::Core::AppViewBackButtonVisibility const&);
            this->shim().AppViewBackButtonVisibility(*reinterpret_cast<Windows::UI::Core::AppViewBackButtonVisibility const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ISystemNavigationManagerStatics> : produce_base<D, Windows::UI::Core::ISystemNavigationManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Core::SystemNavigationManager));
            *loader = detach_from<Windows::UI::Core::SystemNavigationManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::ITouchHitTestingEventArgs> : produce_base<D, Windows::UI::Core::ITouchHitTestingEventArgs>
{
    int32_t WINRT_CALL get_ProximityEvaluation(struct struct_Windows_UI_Core_CoreProximityEvaluation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProximityEvaluation, WINRT_WRAP(Windows::UI::Core::CoreProximityEvaluation));
            *value = detach_from<Windows::UI::Core::CoreProximityEvaluation>(this->shim().ProximityEvaluation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProximityEvaluation(struct struct_Windows_UI_Core_CoreProximityEvaluation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProximityEvaluation, WINRT_WRAP(void), Windows::UI::Core::CoreProximityEvaluation const&);
            this->shim().ProximityEvaluation(*reinterpret_cast<Windows::UI::Core::CoreProximityEvaluation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingBox(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EvaluateProximityToRect(Windows::Foundation::Rect controlBoundingBox, struct struct_Windows_UI_Core_CoreProximityEvaluation* proximityEvaluation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluateProximity, WINRT_WRAP(Windows::UI::Core::CoreProximityEvaluation), Windows::Foundation::Rect const&);
            *proximityEvaluation = detach_from<Windows::UI::Core::CoreProximityEvaluation>(this->shim().EvaluateProximity(*reinterpret_cast<Windows::Foundation::Rect const*>(&controlBoundingBox)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EvaluateProximityToPolygon(uint32_t __controlVerticesSize, Windows::Foundation::Point* controlVertices, struct struct_Windows_UI_Core_CoreProximityEvaluation* proximityEvaluation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EvaluateProximity, WINRT_WRAP(Windows::UI::Core::CoreProximityEvaluation), array_view<Windows::Foundation::Point const>);
            *proximityEvaluation = detach_from<Windows::UI::Core::CoreProximityEvaluation>(this->shim().EvaluateProximity(array_view<Windows::Foundation::Point const>(reinterpret_cast<Windows::Foundation::Point const *>(controlVertices), reinterpret_cast<Windows::Foundation::Point const *>(controlVertices) + __controlVerticesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IVisibilityChangedEventArgs> : produce_base<D, Windows::UI::Core::IVisibilityChangedEventArgs>
{
    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IWindowActivatedEventArgs> : produce_base<D, Windows::UI::Core::IWindowActivatedEventArgs>
{
    int32_t WINRT_CALL get_WindowActivationState(Windows::UI::Core::CoreWindowActivationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowActivationState, WINRT_WRAP(Windows::UI::Core::CoreWindowActivationState));
            *value = detach_from<Windows::UI::Core::CoreWindowActivationState>(this->shim().WindowActivationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::IWindowSizeChangedEventArgs> : produce_base<D, Windows::UI::Core::IWindowSizeChangedEventArgs>
{
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

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

inline CoreCursor::CoreCursor(Windows::UI::Core::CoreCursorType const& type, uint32_t id) :
    CoreCursor(impl::call_factory<CoreCursor, Windows::UI::Core::ICoreCursorFactory>([&](auto&& f) { return f.CreateCursor(type, id); }))
{}

inline Windows::UI::Core::CoreWindow CoreWindow::GetForCurrentThread()
{
    return impl::call_factory<CoreWindow, Windows::UI::Core::ICoreWindowStatic>([&](auto&& f) { return f.GetForCurrentThread(); });
}

inline CoreWindowDialog::CoreWindowDialog() :
    CoreWindowDialog(impl::call_factory<CoreWindowDialog>([](auto&& f) { return f.template ActivateInstance<CoreWindowDialog>(); }))
{}

inline CoreWindowDialog::CoreWindowDialog(param::hstring const& title) :
    CoreWindowDialog(impl::call_factory<CoreWindowDialog, Windows::UI::Core::ICoreWindowDialogFactory>([&](auto&& f) { return f.CreateWithTitle(title); }))
{}

inline CoreWindowFlyout::CoreWindowFlyout(Windows::Foundation::Point const& position) :
    CoreWindowFlyout(impl::call_factory<CoreWindowFlyout, Windows::UI::Core::ICoreWindowFlyoutFactory>([&](auto&& f) { return f.Create(position); }))
{}

inline CoreWindowFlyout::CoreWindowFlyout(Windows::Foundation::Point const& position, param::hstring const& title) :
    CoreWindowFlyout(impl::call_factory<CoreWindowFlyout, Windows::UI::Core::ICoreWindowFlyoutFactory>([&](auto&& f) { return f.CreateWithTitle(position, title); }))
{}

inline Windows::UI::Core::CoreWindowResizeManager CoreWindowResizeManager::GetForCurrentView()
{
    return impl::call_factory<CoreWindowResizeManager, Windows::UI::Core::ICoreWindowResizeManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::UI::Core::SystemNavigationManager SystemNavigationManager::GetForCurrentView()
{
    return impl::call_factory<SystemNavigationManager, Windows::UI::Core::ISystemNavigationManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

template <typename L> DispatchedHandler::DispatchedHandler(L handler) :
    DispatchedHandler(impl::make_delegate<DispatchedHandler>(std::forward<L>(handler)))
{}

template <typename F> DispatchedHandler::DispatchedHandler(F* handler) :
    DispatchedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DispatchedHandler::DispatchedHandler(O* object, M method) :
    DispatchedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DispatchedHandler::DispatchedHandler(com_ptr<O>&& object, M method) :
    DispatchedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DispatchedHandler::DispatchedHandler(weak_ref<O>&& object, M method) :
    DispatchedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DispatchedHandler::operator()() const
{
    check_hresult((*(impl::abi_t<DispatchedHandler>**)this)->Invoke());
}

template <typename L> IdleDispatchedHandler::IdleDispatchedHandler(L handler) :
    IdleDispatchedHandler(impl::make_delegate<IdleDispatchedHandler>(std::forward<L>(handler)))
{}

template <typename F> IdleDispatchedHandler::IdleDispatchedHandler(F* handler) :
    IdleDispatchedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(O* object, M method) :
    IdleDispatchedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(com_ptr<O>&& object, M method) :
    IdleDispatchedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> IdleDispatchedHandler::IdleDispatchedHandler(weak_ref<O>&& object, M method) :
    IdleDispatchedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void IdleDispatchedHandler::operator()(Windows::UI::Core::IdleDispatchedHandlerArgs const& e) const
{
    check_hresult((*(impl::abi_t<IdleDispatchedHandler>**)this)->Invoke(get_abi(e)));
}

}

WINRT_EXPORT namespace winrt
{
    struct resume_foreground
    {
        explicit resume_foreground(Windows::UI::Core::CoreDispatcher&& dispatcher, Windows::UI::Core::CoreDispatcherPriority const priority = Windows::UI::Core::CoreDispatcherPriority::Normal) :
            m_dispatcher(std::move(dispatcher)),
            m_priority(priority)
        {
        }

        explicit resume_foreground(Windows::UI::Core::CoreDispatcher const& dispatcher, Windows::UI::Core::CoreDispatcherPriority const priority = Windows::UI::Core::CoreDispatcherPriority::Normal) :
            m_dispatcher(dispatcher),
            m_priority(priority)
        {
        }

        bool await_ready() const
        {
            return m_dispatcher.HasThreadAccess();
        }

        void await_resume() const noexcept
        {
        }

        void await_suspend(std::experimental::coroutine_handle<> handle) const
        {
            m_dispatcher.RunAsync(m_priority, [handle]
            {
                handle();
            });
        }

    private:

        Windows::UI::Core::CoreDispatcher const m_dispatcher;
        Windows::UI::Core::CoreDispatcherPriority const m_priority;
    };
}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Core::IAcceleratorKeyEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IAutomationProviderRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IBackRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IBackRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ICharacterReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICharacterReceivedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IClosestInteractiveBoundsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreAcceleratorKeys> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreAcceleratorKeys> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreClosestInteractiveBoundsRequested> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreComponentFocusable> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreComponentFocusable> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreCursor> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreCursor> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreCursorFactory> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreCursorFactory> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcher> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreDispatcher> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcher2> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreDispatcher2> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreDispatcherWithTaskPriority> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreInputSourceBase> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreInputSourceBase> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreKeyboardInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreKeyboardInputSource> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreKeyboardInputSource2> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreKeyboardInputSource2> {};
template<> struct hash<winrt::Windows::UI::Core::ICorePointerInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICorePointerInputSource> {};
template<> struct hash<winrt::Windows::UI::Core::ICorePointerInputSource2> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICorePointerInputSource2> {};
template<> struct hash<winrt::Windows::UI::Core::ICorePointerRedirector> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICorePointerRedirector> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreTouchHitTesting> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreTouchHitTesting> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindow> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindow> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindow2> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindow2> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindow3> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindow3> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindow4> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindow4> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindow5> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindow5> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowDialog> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowDialog> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowDialogFactory> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowDialogFactory> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowFlyout> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowFlyout> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowFlyoutFactory> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowFlyoutFactory> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowPopupShowingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManager> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowResizeManager> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowResizeManagerLayoutCapability> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowResizeManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowStatic> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowStatic> {};
template<> struct hash<winrt::Windows::UI::Core::ICoreWindowWithContext> : winrt::impl::hash_base<winrt::Windows::UI::Core::ICoreWindowWithContext> {};
template<> struct hash<winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IIdleDispatchedHandlerArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IInitializeWithCoreWindow> : winrt::impl::hash_base<winrt::Windows::UI::Core::IInitializeWithCoreWindow> {};
template<> struct hash<winrt::Windows::UI::Core::IInputEnabledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IInputEnabledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IKeyEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IKeyEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IKeyEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Core::IKeyEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Core::IPointerEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IPointerEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManager> : winrt::impl::hash_base<winrt::Windows::UI::Core::ISystemNavigationManager> {};
template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManager2> : winrt::impl::hash_base<winrt::Windows::UI::Core::ISystemNavigationManager2> {};
template<> struct hash<winrt::Windows::UI::Core::ISystemNavigationManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Core::ISystemNavigationManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Core::ITouchHitTestingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::ITouchHitTestingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IVisibilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IVisibilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IWindowActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IWindowActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::IWindowSizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IWindowSizeChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::AcceleratorKeyEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::AcceleratorKeyEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::AutomationProviderRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::BackRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::BackRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::CharacterReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::CharacterReceivedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::ClosestInteractiveBoundsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::CoreAcceleratorKeys> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreAcceleratorKeys> {};
template<> struct hash<winrt::Windows::UI::Core::CoreComponentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreComponentInputSource> {};
template<> struct hash<winrt::Windows::UI::Core::CoreCursor> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreCursor> {};
template<> struct hash<winrt::Windows::UI::Core::CoreDispatcher> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreDispatcher> {};
template<> struct hash<winrt::Windows::UI::Core::CoreIndependentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreIndependentInputSource> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindow> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindow> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindowDialog> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindowDialog> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindowEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindowEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindowFlyout> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindowFlyout> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindowPopupShowingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::CoreWindowResizeManager> : winrt::impl::hash_base<winrt::Windows::UI::Core::CoreWindowResizeManager> {};
template<> struct hash<winrt::Windows::UI::Core::IdleDispatchedHandlerArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::IdleDispatchedHandlerArgs> {};
template<> struct hash<winrt::Windows::UI::Core::InputEnabledEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::InputEnabledEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::KeyEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::KeyEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::PointerEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::PointerEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::SystemNavigationManager> : winrt::impl::hash_base<winrt::Windows::UI::Core::SystemNavigationManager> {};
template<> struct hash<winrt::Windows::UI::Core::TouchHitTestingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::TouchHitTestingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::VisibilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::VisibilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::WindowActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::WindowActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::WindowSizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::WindowSizeChangedEventArgs> {};

}
