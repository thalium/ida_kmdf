// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Input.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.Core.1.h"
#include "winrt/impl/Windows.UI.Input.1.h"
#include "winrt/impl/Windows.UI.Xaml.1.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.1.h"
#include "winrt/impl/Windows.UI.Xaml.Input.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input {

struct DoubleTappedEventHandler : Windows::Foundation::IUnknown
{
    DoubleTappedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> DoubleTappedEventHandler(L lambda);
    template <typename F> DoubleTappedEventHandler(F* function);
    template <typename O, typename M> DoubleTappedEventHandler(O* object, M method);
    template <typename O, typename M> DoubleTappedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> DoubleTappedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs const& e) const;
};

struct HoldingEventHandler : Windows::Foundation::IUnknown
{
    HoldingEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> HoldingEventHandler(L lambda);
    template <typename F> HoldingEventHandler(F* function);
    template <typename O, typename M> HoldingEventHandler(O* object, M method);
    template <typename O, typename M> HoldingEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> HoldingEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::HoldingRoutedEventArgs const& e) const;
};

struct KeyEventHandler : Windows::Foundation::IUnknown
{
    KeyEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> KeyEventHandler(L lambda);
    template <typename F> KeyEventHandler(F* function);
    template <typename O, typename M> KeyEventHandler(O* object, M method);
    template <typename O, typename M> KeyEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> KeyEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::KeyRoutedEventArgs const& e) const;
};

struct ManipulationCompletedEventHandler : Windows::Foundation::IUnknown
{
    ManipulationCompletedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ManipulationCompletedEventHandler(L lambda);
    template <typename F> ManipulationCompletedEventHandler(F* function);
    template <typename O, typename M> ManipulationCompletedEventHandler(O* object, M method);
    template <typename O, typename M> ManipulationCompletedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ManipulationCompletedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs const& e) const;
};

struct ManipulationDeltaEventHandler : Windows::Foundation::IUnknown
{
    ManipulationDeltaEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ManipulationDeltaEventHandler(L lambda);
    template <typename F> ManipulationDeltaEventHandler(F* function);
    template <typename O, typename M> ManipulationDeltaEventHandler(O* object, M method);
    template <typename O, typename M> ManipulationDeltaEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ManipulationDeltaEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs const& e) const;
};

struct ManipulationInertiaStartingEventHandler : Windows::Foundation::IUnknown
{
    ManipulationInertiaStartingEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ManipulationInertiaStartingEventHandler(L lambda);
    template <typename F> ManipulationInertiaStartingEventHandler(F* function);
    template <typename O, typename M> ManipulationInertiaStartingEventHandler(O* object, M method);
    template <typename O, typename M> ManipulationInertiaStartingEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ManipulationInertiaStartingEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs const& e) const;
};

struct ManipulationStartedEventHandler : Windows::Foundation::IUnknown
{
    ManipulationStartedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ManipulationStartedEventHandler(L lambda);
    template <typename F> ManipulationStartedEventHandler(F* function);
    template <typename O, typename M> ManipulationStartedEventHandler(O* object, M method);
    template <typename O, typename M> ManipulationStartedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ManipulationStartedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs const& e) const;
};

struct ManipulationStartingEventHandler : Windows::Foundation::IUnknown
{
    ManipulationStartingEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> ManipulationStartingEventHandler(L lambda);
    template <typename F> ManipulationStartingEventHandler(F* function);
    template <typename O, typename M> ManipulationStartingEventHandler(O* object, M method);
    template <typename O, typename M> ManipulationStartingEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> ManipulationStartingEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs const& e) const;
};

struct PointerEventHandler : Windows::Foundation::IUnknown
{
    PointerEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> PointerEventHandler(L lambda);
    template <typename F> PointerEventHandler(F* function);
    template <typename O, typename M> PointerEventHandler(O* object, M method);
    template <typename O, typename M> PointerEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> PointerEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::PointerRoutedEventArgs const& e) const;
};

struct RightTappedEventHandler : Windows::Foundation::IUnknown
{
    RightTappedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> RightTappedEventHandler(L lambda);
    template <typename F> RightTappedEventHandler(F* function);
    template <typename O, typename M> RightTappedEventHandler(O* object, M method);
    template <typename O, typename M> RightTappedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> RightTappedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::RightTappedRoutedEventArgs const& e) const;
};

struct TappedEventHandler : Windows::Foundation::IUnknown
{
    TappedEventHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> TappedEventHandler(L lambda);
    template <typename F> TappedEventHandler(F* function);
    template <typename O, typename M> TappedEventHandler(O* object, M method);
    template <typename O, typename M> TappedEventHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> TappedEventHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Input::TappedRoutedEventArgs const& e) const;
};

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input {

struct WINRT_EBO AccessKeyDisplayDismissedEventArgs :
    Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs
{
    AccessKeyDisplayDismissedEventArgs(std::nullptr_t) noexcept {}
    AccessKeyDisplayDismissedEventArgs();
};

struct WINRT_EBO AccessKeyDisplayRequestedEventArgs :
    Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs
{
    AccessKeyDisplayRequestedEventArgs(std::nullptr_t) noexcept {}
    AccessKeyDisplayRequestedEventArgs();
};

struct WINRT_EBO AccessKeyInvokedEventArgs :
    Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs
{
    AccessKeyInvokedEventArgs(std::nullptr_t) noexcept {}
    AccessKeyInvokedEventArgs();
};

struct WINRT_EBO AccessKeyManager :
    Windows::UI::Xaml::Input::IAccessKeyManager
{
    AccessKeyManager(std::nullptr_t) noexcept {}
    static bool IsDisplayModeEnabled();
    static winrt::event_token IsDisplayModeEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler);
    using IsDisplayModeEnabledChanged_revoker = impl::factory_event_revoker<Windows::UI::Xaml::Input::IAccessKeyManagerStatics, &impl::abi_t<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>::remove_IsDisplayModeEnabledChanged>;
    static IsDisplayModeEnabledChanged_revoker IsDisplayModeEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler);
    static void IsDisplayModeEnabledChanged(winrt::event_token const& token);
    static void ExitDisplayMode();
    static bool AreKeyTipsEnabled();
    static void AreKeyTipsEnabled(bool value);
};

struct WINRT_EBO CanExecuteRequestedEventArgs :
    Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs
{
    CanExecuteRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CharacterReceivedRoutedEventArgs :
    Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs,
    impl::base<CharacterReceivedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<CharacterReceivedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    CharacterReceivedRoutedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ContextRequestedEventArgs :
    Windows::UI::Xaml::Input::IContextRequestedEventArgs,
    impl::base<ContextRequestedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ContextRequestedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ContextRequestedEventArgs(std::nullptr_t) noexcept {}
    ContextRequestedEventArgs();
};

struct WINRT_EBO DoubleTappedRoutedEventArgs :
    Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs,
    impl::base<DoubleTappedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<DoubleTappedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    DoubleTappedRoutedEventArgs(std::nullptr_t) noexcept {}
    DoubleTappedRoutedEventArgs();
};

struct WINRT_EBO ExecuteRequestedEventArgs :
    Windows::UI::Xaml::Input::IExecuteRequestedEventArgs
{
    ExecuteRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FindNextElementOptions :
    Windows::UI::Xaml::Input::IFindNextElementOptions
{
    FindNextElementOptions(std::nullptr_t) noexcept {}
    FindNextElementOptions();
};

struct WINRT_EBO FocusManager :
    Windows::UI::Xaml::Input::IFocusManager
{
    FocusManager(std::nullptr_t) noexcept {}
    static Windows::Foundation::IInspectable GetFocusedElement();
    static bool TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection);
    static Windows::UI::Xaml::UIElement FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection);
    static Windows::UI::Xaml::UIElement FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::Foundation::Rect const& hintRect);
    static bool TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions);
    static Windows::UI::Xaml::DependencyObject FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection);
    static Windows::UI::Xaml::DependencyObject FindFirstFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope);
    static Windows::UI::Xaml::DependencyObject FindLastFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope);
    static Windows::UI::Xaml::DependencyObject FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions);
    static Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryFocusAsync(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FocusState const& value);
    static Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection);
    static Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions);
    static winrt::event_token GotFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler);
    using GotFocus_revoker = impl::factory_event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_GotFocus>;
    static GotFocus_revoker GotFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler);
    static void GotFocus(winrt::event_token const& token);
    static winrt::event_token LostFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler);
    using LostFocus_revoker = impl::factory_event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_LostFocus>;
    static LostFocus_revoker LostFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler);
    static void LostFocus(winrt::event_token const& token);
    static winrt::event_token GettingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler);
    using GettingFocus_revoker = impl::factory_event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_GettingFocus>;
    static GettingFocus_revoker GettingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler);
    static void GettingFocus(winrt::event_token const& token);
    static winrt::event_token LosingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler);
    using LosingFocus_revoker = impl::factory_event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_LosingFocus>;
    static LosingFocus_revoker LosingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler);
    static void LosingFocus(winrt::event_token const& token);
    static Windows::Foundation::IInspectable GetFocusedElement(Windows::UI::Xaml::XamlRoot const& xamlRoot);
};

struct WINRT_EBO FocusManagerGotFocusEventArgs :
    Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs
{
    FocusManagerGotFocusEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FocusManagerLostFocusEventArgs :
    Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs
{
    FocusManagerLostFocusEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FocusMovementResult :
    Windows::UI::Xaml::Input::IFocusMovementResult
{
    FocusMovementResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GettingFocusEventArgs :
    Windows::UI::Xaml::Input::IGettingFocusEventArgs,
    impl::base<GettingFocusEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<GettingFocusEventArgs, Windows::UI::Xaml::IRoutedEventArgs, Windows::UI::Xaml::Input::IGettingFocusEventArgs2, Windows::UI::Xaml::Input::IGettingFocusEventArgs3>
{
    GettingFocusEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HoldingRoutedEventArgs :
    Windows::UI::Xaml::Input::IHoldingRoutedEventArgs,
    impl::base<HoldingRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<HoldingRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    HoldingRoutedEventArgs(std::nullptr_t) noexcept {}
    HoldingRoutedEventArgs();
};

struct WINRT_EBO InertiaExpansionBehavior :
    Windows::UI::Xaml::Input::IInertiaExpansionBehavior
{
    InertiaExpansionBehavior(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InertiaRotationBehavior :
    Windows::UI::Xaml::Input::IInertiaRotationBehavior
{
    InertiaRotationBehavior(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InertiaTranslationBehavior :
    Windows::UI::Xaml::Input::IInertiaTranslationBehavior
{
    InertiaTranslationBehavior(std::nullptr_t) noexcept {}
};

struct WINRT_EBO InputScope :
    Windows::UI::Xaml::Input::IInputScope,
    impl::base<InputScope, Windows::UI::Xaml::DependencyObject>,
    impl::require<InputScope, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>
{
    InputScope(std::nullptr_t) noexcept {}
    InputScope();
};

struct WINRT_EBO InputScopeName :
    Windows::UI::Xaml::Input::IInputScopeName,
    impl::base<InputScopeName, Windows::UI::Xaml::DependencyObject>,
    impl::require<InputScopeName, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>
{
    InputScopeName(std::nullptr_t) noexcept {}
    InputScopeName();
    InputScopeName(Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue);
};

struct WINRT_EBO KeyRoutedEventArgs :
    Windows::UI::Xaml::Input::IKeyRoutedEventArgs,
    impl::base<KeyRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<KeyRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs, Windows::UI::Xaml::Input::IKeyRoutedEventArgs2, Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>
{
    KeyRoutedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO KeyboardAccelerator :
    Windows::UI::Xaml::Input::IKeyboardAccelerator,
    impl::base<KeyboardAccelerator, Windows::UI::Xaml::DependencyObject>,
    impl::require<KeyboardAccelerator, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>
{
    KeyboardAccelerator(std::nullptr_t) noexcept {}
    KeyboardAccelerator();
    static Windows::UI::Xaml::DependencyProperty KeyProperty();
    static Windows::UI::Xaml::DependencyProperty ModifiersProperty();
    static Windows::UI::Xaml::DependencyProperty IsEnabledProperty();
    static Windows::UI::Xaml::DependencyProperty ScopeOwnerProperty();
};

struct WINRT_EBO KeyboardAcceleratorInvokedEventArgs :
    Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs,
    impl::require<KeyboardAcceleratorInvokedEventArgs, Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>
{
    KeyboardAcceleratorInvokedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LosingFocusEventArgs :
    Windows::UI::Xaml::Input::ILosingFocusEventArgs,
    impl::base<LosingFocusEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<LosingFocusEventArgs, Windows::UI::Xaml::IRoutedEventArgs, Windows::UI::Xaml::Input::ILosingFocusEventArgs2, Windows::UI::Xaml::Input::ILosingFocusEventArgs3>
{
    LosingFocusEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ManipulationCompletedRoutedEventArgs :
    Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs,
    impl::base<ManipulationCompletedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ManipulationCompletedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ManipulationCompletedRoutedEventArgs(std::nullptr_t) noexcept {}
    ManipulationCompletedRoutedEventArgs();
};

struct WINRT_EBO ManipulationDeltaRoutedEventArgs :
    Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs,
    impl::base<ManipulationDeltaRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ManipulationDeltaRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ManipulationDeltaRoutedEventArgs(std::nullptr_t) noexcept {}
    ManipulationDeltaRoutedEventArgs();
};

struct WINRT_EBO ManipulationInertiaStartingRoutedEventArgs :
    Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs,
    impl::base<ManipulationInertiaStartingRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ManipulationInertiaStartingRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ManipulationInertiaStartingRoutedEventArgs(std::nullptr_t) noexcept {}
    ManipulationInertiaStartingRoutedEventArgs();
};

struct WINRT_EBO ManipulationPivot :
    Windows::UI::Xaml::Input::IManipulationPivot
{
    ManipulationPivot(std::nullptr_t) noexcept {}
    ManipulationPivot();
    ManipulationPivot(Windows::Foundation::Point const& center, double radius);
};

struct WINRT_EBO ManipulationStartedRoutedEventArgs :
    Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs,
    impl::base<ManipulationStartedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ManipulationStartedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ManipulationStartedRoutedEventArgs(std::nullptr_t) noexcept {}
    ManipulationStartedRoutedEventArgs();
};

struct WINRT_EBO ManipulationStartingRoutedEventArgs :
    Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs,
    impl::base<ManipulationStartingRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<ManipulationStartingRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    ManipulationStartingRoutedEventArgs(std::nullptr_t) noexcept {}
    ManipulationStartingRoutedEventArgs();
};

struct WINRT_EBO NoFocusCandidateFoundEventArgs :
    Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs,
    impl::base<NoFocusCandidateFoundEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<NoFocusCandidateFoundEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    NoFocusCandidateFoundEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Pointer :
    Windows::UI::Xaml::Input::IPointer
{
    Pointer(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PointerRoutedEventArgs :
    Windows::UI::Xaml::Input::IPointerRoutedEventArgs,
    impl::base<PointerRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<PointerRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs, Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>
{
    PointerRoutedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessKeyboardAcceleratorEventArgs :
    Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs
{
    ProcessKeyboardAcceleratorEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO RightTappedRoutedEventArgs :
    Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs,
    impl::base<RightTappedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<RightTappedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    RightTappedRoutedEventArgs(std::nullptr_t) noexcept {}
    RightTappedRoutedEventArgs();
};

struct WINRT_EBO StandardUICommand :
    Windows::UI::Xaml::Input::IStandardUICommand,
    impl::base<StandardUICommand, Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::DependencyObject>,
    impl::require<StandardUICommand, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Input::ICommand, Windows::UI::Xaml::Input::IStandardUICommand2, Windows::UI::Xaml::Input::IXamlUICommand>
{
    StandardUICommand(std::nullptr_t) noexcept {}
    StandardUICommand();
    StandardUICommand(Windows::UI::Xaml::Input::StandardUICommandKind const& kind);
    using impl::consume_t<StandardUICommand, Windows::UI::Xaml::Input::IStandardUICommand2>::Kind;
    using Windows::UI::Xaml::Input::IStandardUICommand::Kind;
    static Windows::UI::Xaml::DependencyProperty KindProperty();
};

struct WINRT_EBO TappedRoutedEventArgs :
    Windows::UI::Xaml::Input::ITappedRoutedEventArgs,
    impl::base<TappedRoutedEventArgs, Windows::UI::Xaml::RoutedEventArgs>,
    impl::require<TappedRoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgs>
{
    TappedRoutedEventArgs(std::nullptr_t) noexcept {}
    TappedRoutedEventArgs();
};

struct WINRT_EBO XamlUICommand :
    Windows::UI::Xaml::Input::IXamlUICommand,
    impl::base<XamlUICommand, Windows::UI::Xaml::DependencyObject>,
    impl::require<XamlUICommand, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Input::ICommand>
{
    XamlUICommand(std::nullptr_t) noexcept {}
    XamlUICommand();
    static Windows::UI::Xaml::DependencyProperty LabelProperty();
    static Windows::UI::Xaml::DependencyProperty IconSourceProperty();
    static Windows::UI::Xaml::DependencyProperty KeyboardAcceleratorsProperty();
    static Windows::UI::Xaml::DependencyProperty AccessKeyProperty();
    static Windows::UI::Xaml::DependencyProperty DescriptionProperty();
    static Windows::UI::Xaml::DependencyProperty CommandProperty();
};

}
