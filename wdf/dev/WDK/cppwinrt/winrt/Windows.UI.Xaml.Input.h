// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Input.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_UI_Xaml_Input_IAccessKeyDisplayRequestedEventArgs<D>::PressedKeys() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs)->get_PressedKeys(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs)->put_Handled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->get_IsDisplayModeEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->add_IsDisplayModeEnabledChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged_revoker consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsDisplayModeEnabledChanged_revoker>(this, IsDisplayModeEnabledChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::IsDisplayModeEnabledChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->remove_IsDisplayModeEnabledChanged(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>::ExitDisplayMode() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics)->ExitDisplayMode());
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2<D>::AreKeyTipsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics2)->get_AreKeyTipsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2<D>::AreKeyTipsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IAccessKeyManagerStatics2)->put_AreKeyTipsEnabled(value));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::Parameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->get_Parameter(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::CanExecute() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->get_CanExecute(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>::CanExecute(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs)->put_CanExecute(value));
}

template <typename D> char16_t consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Character() const
{
    char16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_Character(&value));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs)->put_Handled(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICommand)->add_CanExecuteChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged_revoker consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CanExecuteChanged_revoker>(this, CanExecuteChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecuteChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::ICommand)->remove_CanExecuteChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ICommand<D>::CanExecute(Windows::Foundation::IInspectable const& parameter) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICommand)->CanExecute(get_abi(parameter), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ICommand<D>::Execute(Windows::Foundation::IInspectable const& parameter) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ICommand)->Execute(get_abi(parameter)));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IContextRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IContextRequestedEventArgs)->put_Handled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>::TryGetPosition(Windows::UI::Xaml::UIElement const& relativeTo, Windows::Foundation::Point& point) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IContextRequestedEventArgs)->TryGetPosition(get_abi(relativeTo), put_abi(point), &returnValue));
    return returnValue;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Input_IExecuteRequestedEventArgs<D>::Parameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IExecuteRequestedEventArgs)->get_Parameter(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::SearchRoot() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->get_SearchRoot(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::SearchRoot(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->put_SearchRoot(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::ExclusionRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->get_ExclusionRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::ExclusionRect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->put_ExclusionRect(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::HintRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->get_HintRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::HintRect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->put_HintRect(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::XYFocusNavigationStrategyOverride() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->get_XYFocusNavigationStrategyOverride(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>::XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFindNextElementOptions)->put_XYFocusNavigationStrategyOverride(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs<D>::NewFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs)->get_NewFocusedElement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs<D>::CorrelationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs<D>::OldFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs)->get_OldFocusedElement(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs<D>::CorrelationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Input_IFocusManagerStatics<D>::GetFocusedElement() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics)->GetFocusedElement(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IFocusManagerStatics2<D>::TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics2)->TryMoveFocus(get_abi(focusNavigationDirection), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IFocusManagerStatics3<D>::FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics3)->FindNextFocusableElement(get_abi(focusNavigationDirection), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IFocusManagerStatics3<D>::FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::Foundation::Rect const& hintRect) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics3)->FindNextFocusableElementWithHint(get_abi(focusNavigationDirection), get_abi(hintRect), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics4)->TryMoveFocusWithOptions(get_abi(focusNavigationDirection), get_abi(focusNavigationOptions), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindNextElement(get_abi(focusNavigationDirection), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindFirstFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindFirstFocusableElement(get_abi(searchScope), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindLastFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindLastFocusableElement(get_abi(searchScope), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>::FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics4)->FindNextElementWithOptions(get_abi(focusNavigationDirection), get_abi(focusNavigationOptions), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryFocusAsync(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FocusState const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryFocusAsync(get_abi(element), get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryMoveFocusAsync(get_abi(focusNavigationDirection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>::TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics5)->TryMoveFocusWithOptionsAsync(get_abi(focusNavigationDirection), get_abi(focusNavigationOptions), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_GotFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_LostFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LostFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_LostFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_GettingFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GettingFocus_revoker>(this, GettingFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::GettingFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_GettingFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->add_LosingFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus_revoker consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LosingFocus_revoker>(this, LosingFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>::LosingFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics6)->remove_LosingFocus(get_abi(token)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Input_IFocusManagerStatics7<D>::GetFocusedElement(Windows::UI::Xaml::XamlRoot const& xamlRoot) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusManagerStatics7)->GetFocusedElement(get_abi(xamlRoot), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IFocusMovementResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IFocusMovementResult)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::OldFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_OldFocusedElement(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::NewFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_NewFocusedElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::NewFocusedElement(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_NewFocusedElement(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::FocusState consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::FocusState() const
{
    Windows::UI::Xaml::FocusState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::FocusNavigationDirection consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Direction() const
{
    Windows::UI::Xaml::Input::FocusNavigationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Input::FocusInputDeviceKind consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::InputDevice() const
{
    Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_InputDevice(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs)->put_Cancel(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2<D>::TryCancel() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs2)->TryCancel(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2<D>::TrySetNewFocusedElement(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs2)->TrySetNewFocusedElement(get_abi(element), &result));
    return result;
}

template <typename D> winrt::guid consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs3<D>::CorrelationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IGettingFocusEventArgs3)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::HoldingState consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::HoldingState() const
{
    Windows::UI::Input::HoldingState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_HoldingState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IHoldingRoutedEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredDeceleration() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->get_DesiredDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredDeceleration(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->put_DesiredDeceleration(value));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredExpansion() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->get_DesiredExpansion(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>::DesiredExpansion(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaExpansionBehavior)->put_DesiredExpansion(value));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredDeceleration() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaRotationBehavior)->get_DesiredDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredDeceleration(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaRotationBehavior)->put_DesiredDeceleration(value));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredRotation() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaRotationBehavior)->get_DesiredRotation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>::DesiredRotation(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaRotationBehavior)->put_DesiredRotation(value));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDeceleration() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->get_DesiredDeceleration(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDeceleration(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->put_DesiredDeceleration(value));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDisplacement() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->get_DesiredDisplacement(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>::DesiredDisplacement(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInertiaTranslationBehavior)->put_DesiredDisplacement(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::InputScopeName> consume_Windows_UI_Xaml_Input_IInputScope<D>::Names() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::InputScopeName> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInputScope)->get_Names(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::InputScopeNameValue consume_Windows_UI_Xaml_Input_IInputScopeName<D>::NameValue() const
{
    Windows::UI::Xaml::Input::InputScopeNameValue value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInputScopeName)->get_NameValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IInputScopeName<D>::NameValue(Windows::UI::Xaml::Input::InputScopeNameValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInputScopeName)->put_NameValue(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::InputScopeName consume_Windows_UI_Xaml_Input_IInputScopeNameFactory<D>::CreateInstance(Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue) const
{
    Windows::UI::Xaml::Input::InputScopeName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IInputScopeNameFactory)->CreateInstance(get_abi(nameValue), put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Key() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_Key(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs2<D>::OriginalKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs2)->get_OriginalKey(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs3<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyRoutedEventArgs3)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Key() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_Key(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Key(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_Key(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Modifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_Modifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Modifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_Modifiers(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_IsEnabled(value));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::ScopeOwner() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->get_ScopeOwner(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::ScopeOwner(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->put_ScopeOwner(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->add_Invoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked_revoker consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Invoked_revoker>(this, Invoked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>::Invoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAccelerator)->remove_Invoked(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Input::KeyboardAccelerator consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Input::KeyboardAccelerator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>::Element() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs)->get_Element(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::KeyboardAccelerator consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs2<D>::KeyboardAccelerator() const
{
    Windows::UI::Xaml::Input::KeyboardAccelerator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2)->get_KeyboardAccelerator(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::KeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_KeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::ModifiersProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_ModifiersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::IsEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_IsEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>::ScopeOwnerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics)->get_ScopeOwnerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::OldFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_OldFocusedElement(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::NewFocusedElement() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_NewFocusedElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::NewFocusedElement(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_NewFocusedElement(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::FocusState consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::FocusState() const
{
    Windows::UI::Xaml::FocusState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::FocusNavigationDirection consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Direction() const
{
    Windows::UI::Xaml::Input::FocusNavigationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Input::FocusInputDeviceKind consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::InputDevice() const
{
    Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_InputDevice(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs)->put_Cancel(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2<D>::TryCancel() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs2)->TryCancel(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2<D>::TrySetNewFocusedElement(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs2)->TrySetNewFocusedElement(get_abi(element), &result));
    return result;
}

template <typename D> winrt::guid consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs3<D>::CorrelationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ILosingFocusEventArgs3)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Container() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Container(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::IsInertial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_IsInertial(&value));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Container() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Container(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::IsInertial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_IsInertial(&value));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Delta() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Delta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs)->Complete());
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Container() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Container(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::InertiaExpansionBehavior consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::ExpansionBehavior() const
{
    Windows::UI::Xaml::Input::InertiaExpansionBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_ExpansionBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::ExpansionBehavior(Windows::UI::Xaml::Input::InertiaExpansionBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_ExpansionBehavior(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::InertiaRotationBehavior consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::RotationBehavior() const
{
    Windows::UI::Xaml::Input::InertiaRotationBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_RotationBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::RotationBehavior(Windows::UI::Xaml::Input::InertiaRotationBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_RotationBehavior(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::InertiaTranslationBehavior consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::TranslationBehavior() const
{
    Windows::UI::Xaml::Input::InertiaTranslationBehavior value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_TranslationBehavior(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::TranslationBehavior(Windows::UI::Xaml::Input::InertiaTranslationBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_TranslationBehavior(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Delta() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Delta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationVelocities consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>::Velocities() const
{
    Windows::UI::Input::ManipulationVelocities value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs)->get_Velocities(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Center() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationPivot)->get_Center(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Center(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationPivot)->put_Center(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Radius() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationPivot)->get_Radius(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationPivot<D>::Radius(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationPivot)->put_Radius(value));
}

template <typename D> Windows::UI::Xaml::Input::ManipulationPivot consume_Windows_UI_Xaml_Input_IManipulationPivotFactory<D>::CreateInstanceWithCenterAndRadius(Windows::Foundation::Point const& center, double radius) const
{
    Windows::UI::Xaml::Input::ManipulationPivot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationPivotFactory)->CreateInstanceWithCenterAndRadius(get_abi(center), radius, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Container() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Container(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::ManipulationDelta consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Cumulative() const
{
    Windows::UI::Input::ManipulationDelta value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->get_Cumulative(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs)->Complete());
}

template <typename D> Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::ManipulationModes consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Mode() const
{
    Windows::UI::Xaml::Input::ManipulationModes value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Mode(Windows::UI::Xaml::Input::ManipulationModes const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Mode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Container() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Container(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Container(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Container(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::ManipulationPivot consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Pivot() const
{
    Windows::UI::Xaml::Input::ManipulationPivot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Pivot(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Pivot(Windows::UI::Xaml::Input::ManipulationPivot const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Pivot(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Input::FocusNavigationDirection consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Direction() const
{
    Windows::UI::Xaml::Input::FocusNavigationDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::Input::FocusInputDeviceKind consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>::InputDevice() const
{
    Windows::UI::Xaml::Input::FocusInputDeviceKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs)->get_InputDevice(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Xaml_Input_IPointer<D>::PointerId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointer)->get_PointerId(&value));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IPointer<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointer)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IPointer<D>::IsInContact() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointer)->get_IsInContact(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IPointer<D>::IsInRange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointer)->get_IsInRange(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::Pointer consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Pointer() const
{
    Windows::UI::Xaml::Input::Pointer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_Pointer(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::KeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_KeyModifiers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Input::PointerPoint consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::GetCurrentPoint(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::UI::Input::PointerPoint result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->GetCurrentPoint(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>::GetIntermediatePoints(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs)->GetIntermediatePoints(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs2<D>::IsGenerated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IPointerRoutedEventArgs2)->get_IsGenerated(&value));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Key() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Key(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Modifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Modifiers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Input::StandardUICommandKind consume_Windows_UI_Xaml_Input_IStandardUICommand<D>::Kind() const
{
    Windows::UI::Xaml::Input::StandardUICommandKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IStandardUICommand)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IStandardUICommand2<D>::Kind(Windows::UI::Xaml::Input::StandardUICommandKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IStandardUICommand2)->put_Kind(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::StandardUICommand consume_Windows_UI_Xaml_Input_IStandardUICommandFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Input::StandardUICommand value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IStandardUICommandFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::StandardUICommand consume_Windows_UI_Xaml_Input_IStandardUICommandFactory<D>::CreateInstanceWithKind(Windows::UI::Xaml::Input::StandardUICommandKind const& kind, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Input::StandardUICommand value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IStandardUICommandFactory)->CreateInstanceWithKind(get_abi(kind), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IStandardUICommandStatics<D>::KindProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IStandardUICommandStatics)->get_KindProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::ITappedRoutedEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Label() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_Label(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Label(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->put_Label(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::IconSource consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::IconSource() const
{
    Windows::UI::Xaml::Controls::IconSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_IconSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::IconSource(Windows::UI::Xaml::Controls::IconSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->put_IconSource(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator> consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::KeyboardAccelerators() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_KeyboardAccelerators(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::AccessKey() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_AccessKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::AccessKey(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->put_AccessKey(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->put_Description(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::ICommand consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Command() const
{
    Windows::UI::Xaml::Input::ICommand value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->get_Command(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::Command(Windows::UI::Xaml::Input::ICommand const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->put_Command(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->add_ExecuteRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested_revoker consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ExecuteRequested_revoker>(this, ExecuteRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::ExecuteRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->remove_ExecuteRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->add_CanExecuteRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested_revoker consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CanExecuteRequested_revoker>(this, CanExecuteRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::CanExecuteRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->remove_CanExecuteRequested(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Input_IXamlUICommand<D>::NotifyCanExecuteChanged() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommand)->NotifyCanExecuteChanged());
}

template <typename D> Windows::UI::Xaml::Input::XamlUICommand consume_Windows_UI_Xaml_Input_IXamlUICommandFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Input::XamlUICommand value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::LabelProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_LabelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::IconSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_IconSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::KeyboardAcceleratorsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_KeyboardAcceleratorsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::AccessKeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_AccessKeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::DescriptionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_DescriptionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>::CommandProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Input::IXamlUICommandStatics)->get_CommandProperty(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::UI::Xaml::Input::DoubleTappedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::DoubleTappedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::DoubleTappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::HoldingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::HoldingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::HoldingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::HoldingRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::KeyEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::KeyEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::KeyEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::KeyRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::ManipulationStartedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::ManipulationStartedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::ManipulationStartedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::ManipulationStartingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::ManipulationStartingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::ManipulationStartingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::PointerEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::PointerEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::PointerEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::PointerRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::RightTappedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::RightTappedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::RightTappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::RightTappedRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Input::TappedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Input::TappedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Input::TappedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Input::TappedRoutedEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>
{
    int32_t WINRT_CALL get_PressedKeys(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PressedKeys, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PressedKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>
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
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyManager> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyManager>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyManagerStatics> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>
{
    int32_t WINRT_CALL get_IsDisplayModeEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisplayModeEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisplayModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsDisplayModeEnabledChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisplayModeEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsDisplayModeEnabledChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsDisplayModeEnabledChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsDisplayModeEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsDisplayModeEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL ExitDisplayMode() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayMode, WINRT_WRAP(void));
            this->shim().ExitDisplayMode();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> : produce_base<D, Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>
{
    int32_t WINRT_CALL get_AreKeyTipsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreKeyTipsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreKeyTipsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AreKeyTipsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreKeyTipsEnabled, WINRT_WRAP(void), bool);
            this->shim().AreKeyTipsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>
{
    int32_t WINRT_CALL get_Parameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanExecute(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExecute, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanExecute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanExecute(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExecute, WINRT_WRAP(void), bool);
            this->shim().CanExecute(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>
{
    int32_t WINRT_CALL get_Character(char16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Character, WINRT_WRAP(char16_t));
            *value = detach_from<char16_t>(this->shim().Character());
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
struct produce<D, Windows::UI::Xaml::Input::ICommand> : produce_base<D, Windows::UI::Xaml::Input::ICommand>
{
    int32_t WINRT_CALL add_CanExecuteChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExecuteChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CanExecuteChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CanExecuteChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CanExecuteChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CanExecuteChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CanExecute(void* parameter, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExecute, WINRT_WRAP(bool), Windows::Foundation::IInspectable const&);
            *result = detach_from<bool>(this->shim().CanExecute(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&parameter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Execute(void* parameter) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Execute, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Execute(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&parameter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IContextRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IContextRequestedEventArgs>
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

    int32_t WINRT_CALL TryGetPosition(void* relativeTo, Windows::Foundation::Point* point, bool* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetPosition, WINRT_WRAP(bool), Windows::UI::Xaml::UIElement const&, Windows::Foundation::Point&);
            *returnValue = detach_from<bool>(this->shim().TryGetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo), *reinterpret_cast<Windows::Foundation::Point*>(point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>
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

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>
{
    int32_t WINRT_CALL get_Parameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Parameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFindNextElementOptions> : produce_base<D, Windows::UI::Xaml::Input::IFindNextElementOptions>
{
    int32_t WINRT_CALL get_SearchRoot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchRoot, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().SearchRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SearchRoot(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchRoot, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().SearchRoot(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExclusionRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExclusionRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ExclusionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExclusionRect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExclusionRect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().ExclusionRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HintRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HintRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().HintRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HintRect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HintRect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().HintRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusNavigationStrategyOverride, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride>(this->shim().XYFocusNavigationStrategyOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusNavigationStrategyOverride, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const&);
            this->shim().XYFocusNavigationStrategyOverride(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManager> : produce_base<D, Windows::UI::Xaml::Input::IFocusManager>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>
{
    int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>
{
    int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics>
{
    int32_t WINRT_CALL GetFocusedElement(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFocusedElement, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics2> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics2>
{
    int32_t WINRT_CALL TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFocus, WINRT_WRAP(bool), Windows::UI::Xaml::Input::FocusNavigationDirection const&);
            *result = detach_from<bool>(this->shim().TryMoveFocus(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics3> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics3>
{
    int32_t WINRT_CALL FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNextFocusableElement, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::UI::Xaml::Input::FocusNavigationDirection const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().FindNextFocusableElement(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindNextFocusableElementWithHint(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, Windows::Foundation::Rect hintRect, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNextFocusableElement, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::UI::Xaml::Input::FocusNavigationDirection const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().FindNextFocusableElement(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<Windows::Foundation::Rect const*>(&hintRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics4> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics4>
{
    int32_t WINRT_CALL TryMoveFocusWithOptions(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFocus, WINRT_WRAP(bool), Windows::UI::Xaml::Input::FocusNavigationDirection const&, Windows::UI::Xaml::Input::FindNextElementOptions const&);
            *result = detach_from<bool>(this->shim().TryMoveFocus(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNextElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::Input::FocusNavigationDirection const&);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().FindNextElement(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindFirstFocusableElement(void* searchScope, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindFirstFocusableElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().FindFirstFocusableElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&searchScope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindLastFocusableElement(void* searchScope, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLastFocusableElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().FindLastFocusableElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&searchScope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindNextElementWithOptions(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNextElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::UI::Xaml::Input::FocusNavigationDirection const&, Windows::UI::Xaml::Input::FindNextElementOptions const&);
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().FindNextElement(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics5> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics5>
{
    int32_t WINRT_CALL TryFocusAsync(void* element, Windows::UI::Xaml::FocusState value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryFocusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>), Windows::UI::Xaml::DependencyObject const, Windows::UI::Xaml::FocusState const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryFocusAsync(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::FocusState const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFocusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>), Windows::UI::Xaml::Input::FocusNavigationDirection const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryMoveFocusAsync(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveFocusWithOptionsAsync(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFocusAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>), Windows::UI::Xaml::Input::FocusNavigationDirection const, Windows::UI::Xaml::Input::FindNextElementOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult>>(this->shim().TryMoveFocusAsync(*reinterpret_cast<Windows::UI::Xaml::Input::FocusNavigationDirection const*>(&focusNavigationDirection), *reinterpret_cast<Windows::UI::Xaml::Input::FindNextElementOptions const*>(&focusNavigationOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics6> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics6>
{
    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GettingFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GettingFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GettingFocus(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GettingFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GettingFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GettingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LosingFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LosingFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LosingFocus(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LosingFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LosingFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LosingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusManagerStatics7> : produce_base<D, Windows::UI::Xaml::Input::IFocusManagerStatics7>
{
    int32_t WINRT_CALL GetFocusedElement(void* xamlRoot, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFocusedElement, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::XamlRoot const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetFocusedElement(*reinterpret_cast<Windows::UI::Xaml::XamlRoot const*>(&xamlRoot)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IFocusMovementResult> : produce_base<D, Windows::UI::Xaml::Input::IFocusMovementResult>
{
    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs>
{
    int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NewFocusedElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFocusedElement, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().NewFocusedElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::UI::Xaml::FocusState));
            *value = detach_from<Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::Xaml::Input::FocusNavigationDirection));
            *value = detach_from<Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevice, WINRT_WRAP(Windows::UI::Xaml::Input::FocusInputDeviceKind));
            *value = detach_from<Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs2> : produce_base<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs2>
{
    int32_t WINRT_CALL TryCancel(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCancel, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetNewFocusedElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetNewFocusedElement, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().TrySetNewFocusedElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs3> : produce_base<D, Windows::UI::Xaml::Input::IGettingFocusEventArgs3>
{
    int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>
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

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInertiaExpansionBehavior> : produce_base<D, Windows::UI::Xaml::Input::IInertiaExpansionBehavior>
{
    int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(void), double);
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredExpansion(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredExpansion, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredExpansion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredExpansion(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredExpansion, WINRT_WRAP(void), double);
            this->shim().DesiredExpansion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInertiaRotationBehavior> : produce_base<D, Windows::UI::Xaml::Input::IInertiaRotationBehavior>
{
    int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(void), double);
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredRotation(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRotation, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredRotation(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRotation, WINRT_WRAP(void), double);
            this->shim().DesiredRotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInertiaTranslationBehavior> : produce_base<D, Windows::UI::Xaml::Input::IInertiaTranslationBehavior>
{
    int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredDeceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDeceleration, WINRT_WRAP(void), double);
            this->shim().DesiredDeceleration(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredDisplacement(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDisplacement, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredDisplacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredDisplacement(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredDisplacement, WINRT_WRAP(void), double);
            this->shim().DesiredDisplacement(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInputScope> : produce_base<D, Windows::UI::Xaml::Input::IInputScope>
{
    int32_t WINRT_CALL get_Names(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Names, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::InputScopeName>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::InputScopeName>>(this->shim().Names());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInputScopeName> : produce_base<D, Windows::UI::Xaml::Input::IInputScopeName>
{
    int32_t WINRT_CALL get_NameValue(Windows::UI::Xaml::Input::InputScopeNameValue* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameValue, WINRT_WRAP(Windows::UI::Xaml::Input::InputScopeNameValue));
            *value = detach_from<Windows::UI::Xaml::Input::InputScopeNameValue>(this->shim().NameValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NameValue(Windows::UI::Xaml::Input::InputScopeNameValue value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameValue, WINRT_WRAP(void), Windows::UI::Xaml::Input::InputScopeNameValue const&);
            this->shim().NameValue(*reinterpret_cast<Windows::UI::Xaml::Input::InputScopeNameValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IInputScopeNameFactory> : produce_base<D, Windows::UI::Xaml::Input::IInputScopeNameFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Input::InputScopeNameValue nameValue, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Input::InputScopeName), Windows::UI::Xaml::Input::InputScopeNameValue const&);
            *value = detach_from<Windows::UI::Xaml::Input::InputScopeName>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Input::InputScopeNameValue const*>(&nameValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs>
{
    int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Key, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().Key());
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
struct produce<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> : produce_base<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>
{
    int32_t WINRT_CALL get_OriginalKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().OriginalKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> : produce_base<D, Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>
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
struct produce<D, Windows::UI::Xaml::Input::IKeyboardAccelerator> : produce_base<D, Windows::UI::Xaml::Input::IKeyboardAccelerator>
{
    int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Key, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().Key());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Key(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Key, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().Key(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Modifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Modifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().Modifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
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

    int32_t WINRT_CALL get_ScopeOwner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScopeOwner, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().ScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScopeOwner(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScopeOwner, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().ScopeOwner(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Invoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Invoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> : produce_base<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Input::KeyboardAccelerator), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Input::KeyboardAccelerator>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>
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

    int32_t WINRT_CALL get_Element(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Element, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().Element());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> : produce_base<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>
{
    int32_t WINRT_CALL get_KeyboardAccelerator(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAccelerator, WINRT_WRAP(Windows::UI::Xaml::Input::KeyboardAccelerator));
            *value = detach_from<Windows::UI::Xaml::Input::KeyboardAccelerator>(this->shim().KeyboardAccelerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> : produce_base<D, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>
{
    int32_t WINRT_CALL get_KeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModifiersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModifiersProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ModifiersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScopeOwnerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScopeOwnerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs> : produce_base<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs>
{
    int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().OldFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFocusedElement, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().NewFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NewFocusedElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFocusedElement, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().NewFocusedElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::UI::Xaml::FocusState));
            *value = detach_from<Windows::UI::Xaml::FocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::Xaml::Input::FocusNavigationDirection));
            *value = detach_from<Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevice, WINRT_WRAP(Windows::UI::Xaml::Input::FocusInputDeviceKind));
            *value = detach_from<Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs2> : produce_base<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs2>
{
    int32_t WINRT_CALL TryCancel(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCancel, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryCancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetNewFocusedElement(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetNewFocusedElement, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().TrySetNewFocusedElement(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs3> : produce_base<D, Windows::UI::Xaml::Input::ILosingFocusEventArgs3>
{
    int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>
{
    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Container());
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>
{
    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Container());
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

    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>
{
    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpansionBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpansionBehavior, WINRT_WRAP(Windows::UI::Xaml::Input::InertiaExpansionBehavior));
            *value = detach_from<Windows::UI::Xaml::Input::InertiaExpansionBehavior>(this->shim().ExpansionBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpansionBehavior(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpansionBehavior, WINRT_WRAP(void), Windows::UI::Xaml::Input::InertiaExpansionBehavior const&);
            this->shim().ExpansionBehavior(*reinterpret_cast<Windows::UI::Xaml::Input::InertiaExpansionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationBehavior, WINRT_WRAP(Windows::UI::Xaml::Input::InertiaRotationBehavior));
            *value = detach_from<Windows::UI::Xaml::Input::InertiaRotationBehavior>(this->shim().RotationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationBehavior(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationBehavior, WINRT_WRAP(void), Windows::UI::Xaml::Input::InertiaRotationBehavior const&);
            this->shim().RotationBehavior(*reinterpret_cast<Windows::UI::Xaml::Input::InertiaRotationBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslationBehavior(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslationBehavior, WINRT_WRAP(Windows::UI::Xaml::Input::InertiaTranslationBehavior));
            *value = detach_from<Windows::UI::Xaml::Input::InertiaTranslationBehavior>(this->shim().TranslationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TranslationBehavior(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslationBehavior, WINRT_WRAP(void), Windows::UI::Xaml::Input::InertiaTranslationBehavior const&);
            this->shim().TranslationBehavior(*reinterpret_cast<Windows::UI::Xaml::Input::InertiaTranslationBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Input::IManipulationPivot> : produce_base<D, Windows::UI::Xaml::Input::IManipulationPivot>
{
    int32_t WINRT_CALL get_Center(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Center(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().Center(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Radius(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Radius(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(void), double);
            this->shim().Radius(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationPivotFactory> : produce_base<D, Windows::UI::Xaml::Input::IManipulationPivotFactory>
{
    int32_t WINRT_CALL CreateInstanceWithCenterAndRadius(Windows::Foundation::Point center, double radius, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithCenterAndRadius, WINRT_WRAP(Windows::UI::Xaml::Input::ManipulationPivot), Windows::Foundation::Point const&, double);
            *value = detach_from<Windows::UI::Xaml::Input::ManipulationPivot>(this->shim().CreateInstanceWithCenterAndRadius(*reinterpret_cast<Windows::Foundation::Point const*>(&center), radius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>
{
    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Container());
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

    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>
{
    int32_t WINRT_CALL get_Mode(Windows::UI::Xaml::Input::ManipulationModes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::UI::Xaml::Input::ManipulationModes));
            *value = detach_from<Windows::UI::Xaml::Input::ManipulationModes>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::UI::Xaml::Input::ManipulationModes value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::UI::Xaml::Input::ManipulationModes const&);
            this->shim().Mode(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationModes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Container(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Container(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Container, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Container(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pivot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pivot, WINRT_WRAP(Windows::UI::Xaml::Input::ManipulationPivot));
            *value = detach_from<Windows::UI::Xaml::Input::ManipulationPivot>(this->shim().Pivot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pivot(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pivot, WINRT_WRAP(void), Windows::UI::Xaml::Input::ManipulationPivot const&);
            this->shim().Pivot(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationPivot const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> : produce_base<D, Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>
{
    int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::Xaml::Input::FocusNavigationDirection));
            *value = detach_from<Windows::UI::Xaml::Input::FocusNavigationDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputDevice, WINRT_WRAP(Windows::UI::Xaml::Input::FocusInputDeviceKind));
            *value = detach_from<Windows::UI::Xaml::Input::FocusInputDeviceKind>(this->shim().InputDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IPointer> : produce_base<D, Windows::UI::Xaml::Input::IPointer>
{
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IPointerRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IPointerRoutedEventArgs>
{
    int32_t WINRT_CALL get_Pointer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pointer, WINRT_WRAP(Windows::UI::Xaml::Input::Pointer));
            *value = detach_from<Windows::UI::Xaml::Input::Pointer>(this->shim().Pointer());
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

    int32_t WINRT_CALL GetCurrentPoint(void* relativeTo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentPoint, WINRT_WRAP(Windows::UI::Input::PointerPoint), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Input::PointerPoint>(this->shim().GetCurrentPoint(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIntermediatePoints(void* relativeTo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIntermediatePoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint>>(this->shim().GetIntermediatePoints(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> : produce_base<D, Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>
{
    int32_t WINRT_CALL get_IsGenerated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGenerated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGenerated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>
{
    int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Key, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().Key());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Modifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>
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

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IStandardUICommand> : produce_base<D, Windows::UI::Xaml::Input::IStandardUICommand>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::Xaml::Input::StandardUICommandKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Xaml::Input::StandardUICommandKind));
            *value = detach_from<Windows::UI::Xaml::Input::StandardUICommandKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IStandardUICommand2> : produce_base<D, Windows::UI::Xaml::Input::IStandardUICommand2>
{
    int32_t WINRT_CALL put_Kind(Windows::UI::Xaml::Input::StandardUICommandKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::UI::Xaml::Input::StandardUICommandKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::UI::Xaml::Input::StandardUICommandKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IStandardUICommandFactory> : produce_base<D, Windows::UI::Xaml::Input::IStandardUICommandFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Input::StandardUICommand), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Input::StandardUICommand>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithKind(Windows::UI::Xaml::Input::StandardUICommandKind kind, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithKind, WINRT_WRAP(Windows::UI::Xaml::Input::StandardUICommand), Windows::UI::Xaml::Input::StandardUICommandKind const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Input::StandardUICommand>(this->shim().CreateInstanceWithKind(*reinterpret_cast<Windows::UI::Xaml::Input::StandardUICommandKind const*>(&kind), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IStandardUICommandStatics> : produce_base<D, Windows::UI::Xaml::Input::IStandardUICommandStatics>
{
    int32_t WINRT_CALL get_KindProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KindProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KindProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::ITappedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::Input::ITappedRoutedEventArgs>
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

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IXamlUICommand> : produce_base<D, Windows::UI::Xaml::Input::IXamlUICommand>
{
    int32_t WINRT_CALL get_Label(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Label(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(void), hstring const&);
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IconSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconSource, WINRT_WRAP(Windows::UI::Xaml::Controls::IconSource));
            *value = detach_from<Windows::UI::Xaml::Controls::IconSource>(this->shim().IconSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IconSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconSource, WINRT_WRAP(void), Windows::UI::Xaml::Controls::IconSource const&);
            this->shim().IconSource(*reinterpret_cast<Windows::UI::Xaml::Controls::IconSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAccelerators(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAccelerators, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator>>(this->shim().KeyboardAccelerators());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessKey(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(void), hstring const&);
            this->shim().AccessKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Command(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Command, WINRT_WRAP(Windows::UI::Xaml::Input::ICommand));
            *value = detach_from<Windows::UI::Xaml::Input::ICommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Command(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Command, WINRT_WRAP(void), Windows::UI::Xaml::Input::ICommand const&);
            this->shim().Command(*reinterpret_cast<Windows::UI::Xaml::Input::ICommand const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ExecuteRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecuteRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ExecuteRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ExecuteRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ExecuteRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ExecuteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CanExecuteRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExecuteRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CanExecuteRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CanExecuteRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CanExecuteRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CanExecuteRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NotifyCanExecuteChanged() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCanExecuteChanged, WINRT_WRAP(void));
            this->shim().NotifyCanExecuteChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IXamlUICommandFactory> : produce_base<D, Windows::UI::Xaml::Input::IXamlUICommandFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Input::XamlUICommand), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Input::XamlUICommand>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Input::IXamlUICommandStatics> : produce_base<D, Windows::UI::Xaml::Input::IXamlUICommandStatics>
{
    int32_t WINRT_CALL get_LabelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LabelProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LabelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IconSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IconSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAcceleratorsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DescriptionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DescriptionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DescriptionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommandProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CommandProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input {

inline AccessKeyDisplayDismissedEventArgs::AccessKeyDisplayDismissedEventArgs() :
    AccessKeyDisplayDismissedEventArgs(impl::call_factory<AccessKeyDisplayDismissedEventArgs>([](auto&& f) { return f.template ActivateInstance<AccessKeyDisplayDismissedEventArgs>(); }))
{}

inline AccessKeyDisplayRequestedEventArgs::AccessKeyDisplayRequestedEventArgs() :
    AccessKeyDisplayRequestedEventArgs(impl::call_factory<AccessKeyDisplayRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<AccessKeyDisplayRequestedEventArgs>(); }))
{}

inline AccessKeyInvokedEventArgs::AccessKeyInvokedEventArgs() :
    AccessKeyInvokedEventArgs(impl::call_factory<AccessKeyInvokedEventArgs>([](auto&& f) { return f.template ActivateInstance<AccessKeyInvokedEventArgs>(); }))
{}

inline bool AccessKeyManager::IsDisplayModeEnabled()
{
    return impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>([&](auto&& f) { return f.IsDisplayModeEnabled(); });
}

inline winrt::event_token AccessKeyManager::IsDisplayModeEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>([&](auto&& f) { return f.IsDisplayModeEnabledChanged(handler); });
}

inline AccessKeyManager::IsDisplayModeEnabledChanged_revoker AccessKeyManager::IsDisplayModeEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>();
    return { f, f.IsDisplayModeEnabledChanged(handler) };
}

inline void AccessKeyManager::IsDisplayModeEnabledChanged(winrt::event_token const& token)
{
    impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>([&](auto&& f) { return f.IsDisplayModeEnabledChanged(token); });
}

inline void AccessKeyManager::ExitDisplayMode()
{
    impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics>([&](auto&& f) { return f.ExitDisplayMode(); });
}

inline bool AccessKeyManager::AreKeyTipsEnabled()
{
    return impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>([&](auto&& f) { return f.AreKeyTipsEnabled(); });
}

inline void AccessKeyManager::AreKeyTipsEnabled(bool value)
{
    impl::call_factory<AccessKeyManager, Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>([&](auto&& f) { return f.AreKeyTipsEnabled(value); });
}

inline ContextRequestedEventArgs::ContextRequestedEventArgs() :
    ContextRequestedEventArgs(impl::call_factory<ContextRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<ContextRequestedEventArgs>(); }))
{}

inline DoubleTappedRoutedEventArgs::DoubleTappedRoutedEventArgs() :
    DoubleTappedRoutedEventArgs(impl::call_factory<DoubleTappedRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<DoubleTappedRoutedEventArgs>(); }))
{}

inline FindNextElementOptions::FindNextElementOptions() :
    FindNextElementOptions(impl::call_factory<FindNextElementOptions>([](auto&& f) { return f.template ActivateInstance<FindNextElementOptions>(); }))
{}

inline Windows::Foundation::IInspectable FocusManager::GetFocusedElement()
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics>([&](auto&& f) { return f.GetFocusedElement(); });
}

inline bool FocusManager::TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics2>([&](auto&& f) { return f.TryMoveFocus(focusNavigationDirection); });
}

inline Windows::UI::Xaml::UIElement FocusManager::FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics3>([&](auto&& f) { return f.FindNextFocusableElement(focusNavigationDirection); });
}

inline Windows::UI::Xaml::UIElement FocusManager::FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::Foundation::Rect const& hintRect)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics3>([&](auto&& f) { return f.FindNextFocusableElement(focusNavigationDirection, hintRect); });
}

inline bool FocusManager::TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics4>([&](auto&& f) { return f.TryMoveFocus(focusNavigationDirection, focusNavigationOptions); });
}

inline Windows::UI::Xaml::DependencyObject FocusManager::FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics4>([&](auto&& f) { return f.FindNextElement(focusNavigationDirection); });
}

inline Windows::UI::Xaml::DependencyObject FocusManager::FindFirstFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics4>([&](auto&& f) { return f.FindFirstFocusableElement(searchScope); });
}

inline Windows::UI::Xaml::DependencyObject FocusManager::FindLastFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics4>([&](auto&& f) { return f.FindLastFocusableElement(searchScope); });
}

inline Windows::UI::Xaml::DependencyObject FocusManager::FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics4>([&](auto&& f) { return f.FindNextElement(focusNavigationDirection, focusNavigationOptions); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> FocusManager::TryFocusAsync(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FocusState const& value)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics5>([&](auto&& f) { return f.TryFocusAsync(element, value); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> FocusManager::TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics5>([&](auto&& f) { return f.TryMoveFocusAsync(focusNavigationDirection); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> FocusManager::TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics5>([&](auto&& f) { return f.TryMoveFocusAsync(focusNavigationDirection, focusNavigationOptions); });
}

inline winrt::event_token FocusManager::GotFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.GotFocus(handler); });
}

inline FocusManager::GotFocus_revoker FocusManager::GotFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler)
{
    auto f = get_activation_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>();
    return { f, f.GotFocus(handler) };
}

inline void FocusManager::GotFocus(winrt::event_token const& token)
{
    impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.GotFocus(token); });
}

inline winrt::event_token FocusManager::LostFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.LostFocus(handler); });
}

inline FocusManager::LostFocus_revoker FocusManager::LostFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler)
{
    auto f = get_activation_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>();
    return { f, f.LostFocus(handler) };
}

inline void FocusManager::LostFocus(winrt::event_token const& token)
{
    impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.LostFocus(token); });
}

inline winrt::event_token FocusManager::GettingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.GettingFocus(handler); });
}

inline FocusManager::GettingFocus_revoker FocusManager::GettingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler)
{
    auto f = get_activation_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>();
    return { f, f.GettingFocus(handler) };
}

inline void FocusManager::GettingFocus(winrt::event_token const& token)
{
    impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.GettingFocus(token); });
}

inline winrt::event_token FocusManager::LosingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.LosingFocus(handler); });
}

inline FocusManager::LosingFocus_revoker FocusManager::LosingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler)
{
    auto f = get_activation_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>();
    return { f, f.LosingFocus(handler) };
}

inline void FocusManager::LosingFocus(winrt::event_token const& token)
{
    impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics6>([&](auto&& f) { return f.LosingFocus(token); });
}

inline Windows::Foundation::IInspectable FocusManager::GetFocusedElement(Windows::UI::Xaml::XamlRoot const& xamlRoot)
{
    return impl::call_factory<FocusManager, Windows::UI::Xaml::Input::IFocusManagerStatics7>([&](auto&& f) { return f.GetFocusedElement(xamlRoot); });
}

inline HoldingRoutedEventArgs::HoldingRoutedEventArgs() :
    HoldingRoutedEventArgs(impl::call_factory<HoldingRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<HoldingRoutedEventArgs>(); }))
{}

inline InputScope::InputScope() :
    InputScope(impl::call_factory<InputScope>([](auto&& f) { return f.template ActivateInstance<InputScope>(); }))
{}

inline InputScopeName::InputScopeName() :
    InputScopeName(impl::call_factory<InputScopeName>([](auto&& f) { return f.template ActivateInstance<InputScopeName>(); }))
{}

inline InputScopeName::InputScopeName(Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue) :
    InputScopeName(impl::call_factory<InputScopeName, Windows::UI::Xaml::Input::IInputScopeNameFactory>([&](auto&& f) { return f.CreateInstance(nameValue); }))
{}

inline KeyboardAccelerator::KeyboardAccelerator()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty KeyboardAccelerator::KeyProperty()
{
    return impl::call_factory<KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>([&](auto&& f) { return f.KeyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty KeyboardAccelerator::ModifiersProperty()
{
    return impl::call_factory<KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>([&](auto&& f) { return f.ModifiersProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty KeyboardAccelerator::IsEnabledProperty()
{
    return impl::call_factory<KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>([&](auto&& f) { return f.IsEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty KeyboardAccelerator::ScopeOwnerProperty()
{
    return impl::call_factory<KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>([&](auto&& f) { return f.ScopeOwnerProperty(); });
}

inline ManipulationCompletedRoutedEventArgs::ManipulationCompletedRoutedEventArgs() :
    ManipulationCompletedRoutedEventArgs(impl::call_factory<ManipulationCompletedRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<ManipulationCompletedRoutedEventArgs>(); }))
{}

inline ManipulationDeltaRoutedEventArgs::ManipulationDeltaRoutedEventArgs() :
    ManipulationDeltaRoutedEventArgs(impl::call_factory<ManipulationDeltaRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<ManipulationDeltaRoutedEventArgs>(); }))
{}

inline ManipulationInertiaStartingRoutedEventArgs::ManipulationInertiaStartingRoutedEventArgs() :
    ManipulationInertiaStartingRoutedEventArgs(impl::call_factory<ManipulationInertiaStartingRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<ManipulationInertiaStartingRoutedEventArgs>(); }))
{}

inline ManipulationPivot::ManipulationPivot() :
    ManipulationPivot(impl::call_factory<ManipulationPivot>([](auto&& f) { return f.template ActivateInstance<ManipulationPivot>(); }))
{}

inline ManipulationPivot::ManipulationPivot(Windows::Foundation::Point const& center, double radius) :
    ManipulationPivot(impl::call_factory<ManipulationPivot, Windows::UI::Xaml::Input::IManipulationPivotFactory>([&](auto&& f) { return f.CreateInstanceWithCenterAndRadius(center, radius); }))
{}

inline ManipulationStartedRoutedEventArgs::ManipulationStartedRoutedEventArgs()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ManipulationStartedRoutedEventArgs, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline ManipulationStartingRoutedEventArgs::ManipulationStartingRoutedEventArgs() :
    ManipulationStartingRoutedEventArgs(impl::call_factory<ManipulationStartingRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<ManipulationStartingRoutedEventArgs>(); }))
{}

inline RightTappedRoutedEventArgs::RightTappedRoutedEventArgs() :
    RightTappedRoutedEventArgs(impl::call_factory<RightTappedRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<RightTappedRoutedEventArgs>(); }))
{}

inline StandardUICommand::StandardUICommand()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommandFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline StandardUICommand::StandardUICommand(Windows::UI::Xaml::Input::StandardUICommandKind const& kind)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommandFactory>([&](auto&& f) { return f.CreateInstanceWithKind(kind, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty StandardUICommand::KindProperty()
{
    return impl::call_factory<StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommandStatics>([&](auto&& f) { return f.KindProperty(); });
}

inline TappedRoutedEventArgs::TappedRoutedEventArgs() :
    TappedRoutedEventArgs(impl::call_factory<TappedRoutedEventArgs>([](auto&& f) { return f.template ActivateInstance<TappedRoutedEventArgs>(); }))
{}

inline XamlUICommand::XamlUICommand()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::LabelProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.LabelProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::IconSourceProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.IconSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::KeyboardAcceleratorsProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.KeyboardAcceleratorsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::AccessKeyProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.AccessKeyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::DescriptionProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.DescriptionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty XamlUICommand::CommandProperty()
{
    return impl::call_factory<XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandStatics>([&](auto&& f) { return f.CommandProperty(); });
}

template <typename L> DoubleTappedEventHandler::DoubleTappedEventHandler(L handler) :
    DoubleTappedEventHandler(impl::make_delegate<DoubleTappedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DoubleTappedEventHandler::DoubleTappedEventHandler(F* handler) :
    DoubleTappedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(O* object, M method) :
    DoubleTappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(com_ptr<O>&& object, M method) :
    DoubleTappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DoubleTappedEventHandler::DoubleTappedEventHandler(weak_ref<O>&& object, M method) :
    DoubleTappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DoubleTappedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DoubleTappedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> HoldingEventHandler::HoldingEventHandler(L handler) :
    HoldingEventHandler(impl::make_delegate<HoldingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> HoldingEventHandler::HoldingEventHandler(F* handler) :
    HoldingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(O* object, M method) :
    HoldingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(com_ptr<O>&& object, M method) :
    HoldingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> HoldingEventHandler::HoldingEventHandler(weak_ref<O>&& object, M method) :
    HoldingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void HoldingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::HoldingRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<HoldingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> KeyEventHandler::KeyEventHandler(L handler) :
    KeyEventHandler(impl::make_delegate<KeyEventHandler>(std::forward<L>(handler)))
{}

template <typename F> KeyEventHandler::KeyEventHandler(F* handler) :
    KeyEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> KeyEventHandler::KeyEventHandler(O* object, M method) :
    KeyEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> KeyEventHandler::KeyEventHandler(com_ptr<O>&& object, M method) :
    KeyEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> KeyEventHandler::KeyEventHandler(weak_ref<O>&& object, M method) :
    KeyEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void KeyEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::KeyRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<KeyEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(L handler) :
    ManipulationCompletedEventHandler(impl::make_delegate<ManipulationCompletedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(F* handler) :
    ManipulationCompletedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(O* object, M method) :
    ManipulationCompletedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(com_ptr<O>&& object, M method) :
    ManipulationCompletedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ManipulationCompletedEventHandler::ManipulationCompletedEventHandler(weak_ref<O>&& object, M method) :
    ManipulationCompletedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ManipulationCompletedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ManipulationCompletedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(L handler) :
    ManipulationDeltaEventHandler(impl::make_delegate<ManipulationDeltaEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(F* handler) :
    ManipulationDeltaEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(O* object, M method) :
    ManipulationDeltaEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(com_ptr<O>&& object, M method) :
    ManipulationDeltaEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ManipulationDeltaEventHandler::ManipulationDeltaEventHandler(weak_ref<O>&& object, M method) :
    ManipulationDeltaEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ManipulationDeltaEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ManipulationDeltaEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(L handler) :
    ManipulationInertiaStartingEventHandler(impl::make_delegate<ManipulationInertiaStartingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(F* handler) :
    ManipulationInertiaStartingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(O* object, M method) :
    ManipulationInertiaStartingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(com_ptr<O>&& object, M method) :
    ManipulationInertiaStartingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ManipulationInertiaStartingEventHandler::ManipulationInertiaStartingEventHandler(weak_ref<O>&& object, M method) :
    ManipulationInertiaStartingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ManipulationInertiaStartingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ManipulationInertiaStartingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ManipulationStartedEventHandler::ManipulationStartedEventHandler(L handler) :
    ManipulationStartedEventHandler(impl::make_delegate<ManipulationStartedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ManipulationStartedEventHandler::ManipulationStartedEventHandler(F* handler) :
    ManipulationStartedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(O* object, M method) :
    ManipulationStartedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(com_ptr<O>&& object, M method) :
    ManipulationStartedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ManipulationStartedEventHandler::ManipulationStartedEventHandler(weak_ref<O>&& object, M method) :
    ManipulationStartedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ManipulationStartedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ManipulationStartedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ManipulationStartingEventHandler::ManipulationStartingEventHandler(L handler) :
    ManipulationStartingEventHandler(impl::make_delegate<ManipulationStartingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ManipulationStartingEventHandler::ManipulationStartingEventHandler(F* handler) :
    ManipulationStartingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(O* object, M method) :
    ManipulationStartingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(com_ptr<O>&& object, M method) :
    ManipulationStartingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ManipulationStartingEventHandler::ManipulationStartingEventHandler(weak_ref<O>&& object, M method) :
    ManipulationStartingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ManipulationStartingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ManipulationStartingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> PointerEventHandler::PointerEventHandler(L handler) :
    PointerEventHandler(impl::make_delegate<PointerEventHandler>(std::forward<L>(handler)))
{}

template <typename F> PointerEventHandler::PointerEventHandler(F* handler) :
    PointerEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PointerEventHandler::PointerEventHandler(O* object, M method) :
    PointerEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PointerEventHandler::PointerEventHandler(com_ptr<O>&& object, M method) :
    PointerEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PointerEventHandler::PointerEventHandler(weak_ref<O>&& object, M method) :
    PointerEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PointerEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::PointerRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<PointerEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> RightTappedEventHandler::RightTappedEventHandler(L handler) :
    RightTappedEventHandler(impl::make_delegate<RightTappedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RightTappedEventHandler::RightTappedEventHandler(F* handler) :
    RightTappedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(O* object, M method) :
    RightTappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(com_ptr<O>&& object, M method) :
    RightTappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RightTappedEventHandler::RightTappedEventHandler(weak_ref<O>&& object, M method) :
    RightTappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RightTappedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::RightTappedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<RightTappedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> TappedEventHandler::TappedEventHandler(L handler) :
    TappedEventHandler(impl::make_delegate<TappedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> TappedEventHandler::TappedEventHandler(F* handler) :
    TappedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> TappedEventHandler::TappedEventHandler(O* object, M method) :
    TappedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> TappedEventHandler::TappedEventHandler(com_ptr<O>&& object, M method) :
    TappedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> TappedEventHandler::TappedEventHandler(weak_ref<O>&& object, M method) :
    TappedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void TappedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<TappedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D, typename... Interfaces>
struct KeyboardAcceleratorT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Input::IKeyboardAccelerator, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::DependencyObject>
{
    using composable = KeyboardAccelerator;

protected:
    KeyboardAcceleratorT()
    {
        impl::call_factory<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ManipulationStartedRoutedEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>,
    impl::base<D, Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>
{
    using composable = ManipulationStartedRoutedEventArgs;

protected:
    ManipulationStartedRoutedEventArgsT()
    {
        impl::call_factory<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs, Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct StandardUICommandT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Input::IStandardUICommand, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Input::ICommand, Windows::UI::Xaml::Input::IStandardUICommand2, Windows::UI::Xaml::Input::IXamlUICommand>,
    impl::base<D, Windows::UI::Xaml::Input::StandardUICommand, Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::DependencyObject>
{
    using composable = StandardUICommand;

protected:
    StandardUICommandT()
    {
        impl::call_factory<Windows::UI::Xaml::Input::StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommandFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    StandardUICommandT(Windows::UI::Xaml::Input::StandardUICommandKind const& kind)
    {
        impl::call_factory<Windows::UI::Xaml::Input::StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommandFactory>([&](auto&& f) { f.CreateInstanceWithKind(kind, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct XamlUICommandT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Input::IXamlUICommand, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Input::ICommand>,
    impl::base<D, Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::DependencyObject>
{
    using composable = XamlUICommand;

protected:
    XamlUICommandT()
    {
        impl::call_factory<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::IXamlUICommandFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ICommand> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ICommand> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFindNextElementOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFindNextElementOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusManagerStatics7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IFocusMovementResult> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IFocusMovementResult> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IGettingFocusEventArgs3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInertiaExpansionBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInertiaRotationBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInertiaTranslationBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScope> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInputScope> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScopeName> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInputScopeName> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IInputScopeNameFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyboardAccelerator> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ILosingFocusEventArgs3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationPivot> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationPivot> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationPivotFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IPointer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommand> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IStandardUICommand> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommand2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IStandardUICommand2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IStandardUICommandFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IStandardUICommandStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ITappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommand> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IXamlUICommand> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IXamlUICommandFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::IXamlUICommandStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::AccessKeyManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::AccessKeyManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::FindNextElementOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::FindNextElementOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::FocusManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::FocusMovementResult> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::FocusMovementResult> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::GettingFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::HoldingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::HoldingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::InertiaExpansionBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::InertiaRotationBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::InertiaTranslationBehavior> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::InputScope> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::InputScope> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::InputScopeName> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::InputScopeName> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::KeyRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::KeyboardAccelerator> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::LosingFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationPivot> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationPivot> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::Pointer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::Pointer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::PointerRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::PointerRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::RightTappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::RightTappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::StandardUICommand> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::StandardUICommand> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::TappedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::TappedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Input::XamlUICommand> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Input::XamlUICommand> {};

}
