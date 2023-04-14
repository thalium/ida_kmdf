// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Input {

enum class PointerDeviceType;

}

WINRT_EXPORT namespace winrt::Windows::System {

enum class VirtualKey;
enum class VirtualKeyModifiers : unsigned;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

struct CorePhysicalKeyStatus;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input {

enum class HoldingState;
struct ManipulationDelta;
struct ManipulationVelocities;
struct PointerPoint;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

enum class FocusState;
struct DependencyObject;
struct DependencyProperty;
struct UIElement;
struct XamlRoot;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls {

struct IconSource;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input {

enum class FocusInputDeviceKind : int32_t
{
    None = 0,
    Mouse = 1,
    Touch = 2,
    Pen = 3,
    Keyboard = 4,
    GameController = 5,
};

enum class FocusNavigationDirection : int32_t
{
    Next = 0,
    Previous = 1,
    Up = 2,
    Down = 3,
    Left = 4,
    Right = 5,
    None = 6,
};

enum class InputScopeNameValue : int32_t
{
    Default = 0,
    Url = 1,
    EmailSmtpAddress = 5,
    PersonalFullName = 7,
    CurrencyAmountAndSymbol = 20,
    CurrencyAmount = 21,
    DateMonthNumber = 23,
    DateDayNumber = 24,
    DateYear = 25,
    Digits = 28,
    Number = 29,
    Password = 31,
    TelephoneNumber = 32,
    TelephoneCountryCode = 33,
    TelephoneAreaCode = 34,
    TelephoneLocalNumber = 35,
    TimeHour = 37,
    TimeMinutesOrSeconds = 38,
    NumberFullWidth = 39,
    AlphanumericHalfWidth = 40,
    AlphanumericFullWidth = 41,
    Hiragana = 44,
    KatakanaHalfWidth = 45,
    KatakanaFullWidth = 46,
    Hanja = 47,
    HangulHalfWidth = 48,
    HangulFullWidth = 49,
    Search = 50,
    Formula = 51,
    SearchIncremental = 52,
    ChineseHalfWidth = 53,
    ChineseFullWidth = 54,
    NativeScript = 55,
    Text = 57,
    Chat = 58,
    NameOrPhoneNumber = 59,
    EmailNameOrAddress = 60,
    Maps = 62,
    NumericPassword = 63,
    NumericPin = 64,
    AlphanumericPin = 65,
    FormulaNumber = 67,
    ChatWithoutEmoji = 68,
};

enum class KeyTipPlacementMode : int32_t
{
    Auto = 0,
    Bottom = 1,
    Top = 2,
    Left = 3,
    Right = 4,
    Center = 5,
    Hidden = 6,
};

enum class KeyboardAcceleratorPlacementMode : int32_t
{
    Auto = 0,
    Hidden = 1,
};

enum class KeyboardNavigationMode : int32_t
{
    Local = 0,
    Cycle = 1,
    Once = 2,
};

enum class ManipulationModes : uint32_t
{
    None = 0x0,
    TranslateX = 0x1,
    TranslateY = 0x2,
    TranslateRailsX = 0x4,
    TranslateRailsY = 0x8,
    Rotate = 0x10,
    Scale = 0x20,
    TranslateInertia = 0x40,
    RotateInertia = 0x80,
    ScaleInertia = 0x100,
    All = 0xFFFF,
    System = 0x10000,
};

enum class StandardUICommandKind : int32_t
{
    None = 0,
    Cut = 1,
    Copy = 2,
    Paste = 3,
    SelectAll = 4,
    Delete = 5,
    Share = 6,
    Save = 7,
    Open = 8,
    Close = 9,
    Pause = 10,
    Play = 11,
    Stop = 12,
    Forward = 13,
    Backward = 14,
    Undo = 15,
    Redo = 16,
};

enum class XYFocusKeyboardNavigationMode : int32_t
{
    Auto = 0,
    Enabled = 1,
    Disabled = 2,
};

enum class XYFocusNavigationStrategy : int32_t
{
    Auto = 0,
    Projection = 1,
    NavigationDirectionDistance = 2,
    RectilinearDistance = 3,
};

enum class XYFocusNavigationStrategyOverride : int32_t
{
    None = 0,
    Auto = 1,
    Projection = 2,
    NavigationDirectionDistance = 3,
    RectilinearDistance = 4,
};

struct IAccessKeyDisplayDismissedEventArgs;
struct IAccessKeyDisplayRequestedEventArgs;
struct IAccessKeyInvokedEventArgs;
struct IAccessKeyManager;
struct IAccessKeyManagerStatics;
struct IAccessKeyManagerStatics2;
struct ICanExecuteRequestedEventArgs;
struct ICharacterReceivedRoutedEventArgs;
struct ICommand;
struct IContextRequestedEventArgs;
struct IDoubleTappedRoutedEventArgs;
struct IExecuteRequestedEventArgs;
struct IFindNextElementOptions;
struct IFocusManager;
struct IFocusManagerGotFocusEventArgs;
struct IFocusManagerLostFocusEventArgs;
struct IFocusManagerStatics;
struct IFocusManagerStatics2;
struct IFocusManagerStatics3;
struct IFocusManagerStatics4;
struct IFocusManagerStatics5;
struct IFocusManagerStatics6;
struct IFocusManagerStatics7;
struct IFocusMovementResult;
struct IGettingFocusEventArgs;
struct IGettingFocusEventArgs2;
struct IGettingFocusEventArgs3;
struct IHoldingRoutedEventArgs;
struct IInertiaExpansionBehavior;
struct IInertiaRotationBehavior;
struct IInertiaTranslationBehavior;
struct IInputScope;
struct IInputScopeName;
struct IInputScopeNameFactory;
struct IKeyRoutedEventArgs;
struct IKeyRoutedEventArgs2;
struct IKeyRoutedEventArgs3;
struct IKeyboardAccelerator;
struct IKeyboardAcceleratorFactory;
struct IKeyboardAcceleratorInvokedEventArgs;
struct IKeyboardAcceleratorInvokedEventArgs2;
struct IKeyboardAcceleratorStatics;
struct ILosingFocusEventArgs;
struct ILosingFocusEventArgs2;
struct ILosingFocusEventArgs3;
struct IManipulationCompletedRoutedEventArgs;
struct IManipulationDeltaRoutedEventArgs;
struct IManipulationInertiaStartingRoutedEventArgs;
struct IManipulationPivot;
struct IManipulationPivotFactory;
struct IManipulationStartedRoutedEventArgs;
struct IManipulationStartedRoutedEventArgsFactory;
struct IManipulationStartingRoutedEventArgs;
struct INoFocusCandidateFoundEventArgs;
struct IPointer;
struct IPointerRoutedEventArgs;
struct IPointerRoutedEventArgs2;
struct IProcessKeyboardAcceleratorEventArgs;
struct IRightTappedRoutedEventArgs;
struct IStandardUICommand;
struct IStandardUICommand2;
struct IStandardUICommandFactory;
struct IStandardUICommandStatics;
struct ITappedRoutedEventArgs;
struct IXamlUICommand;
struct IXamlUICommandFactory;
struct IXamlUICommandStatics;
struct AccessKeyDisplayDismissedEventArgs;
struct AccessKeyDisplayRequestedEventArgs;
struct AccessKeyInvokedEventArgs;
struct AccessKeyManager;
struct CanExecuteRequestedEventArgs;
struct CharacterReceivedRoutedEventArgs;
struct ContextRequestedEventArgs;
struct DoubleTappedRoutedEventArgs;
struct ExecuteRequestedEventArgs;
struct FindNextElementOptions;
struct FocusManager;
struct FocusManagerGotFocusEventArgs;
struct FocusManagerLostFocusEventArgs;
struct FocusMovementResult;
struct GettingFocusEventArgs;
struct HoldingRoutedEventArgs;
struct InertiaExpansionBehavior;
struct InertiaRotationBehavior;
struct InertiaTranslationBehavior;
struct InputScope;
struct InputScopeName;
struct KeyRoutedEventArgs;
struct KeyboardAccelerator;
struct KeyboardAcceleratorInvokedEventArgs;
struct LosingFocusEventArgs;
struct ManipulationCompletedRoutedEventArgs;
struct ManipulationDeltaRoutedEventArgs;
struct ManipulationInertiaStartingRoutedEventArgs;
struct ManipulationPivot;
struct ManipulationStartedRoutedEventArgs;
struct ManipulationStartingRoutedEventArgs;
struct NoFocusCandidateFoundEventArgs;
struct Pointer;
struct PointerRoutedEventArgs;
struct ProcessKeyboardAcceleratorEventArgs;
struct RightTappedRoutedEventArgs;
struct StandardUICommand;
struct TappedRoutedEventArgs;
struct XamlUICommand;
struct DoubleTappedEventHandler;
struct HoldingEventHandler;
struct KeyEventHandler;
struct ManipulationCompletedEventHandler;
struct ManipulationDeltaEventHandler;
struct ManipulationInertiaStartingEventHandler;
struct ManipulationStartedEventHandler;
struct ManipulationStartingEventHandler;
struct PointerEventHandler;
struct RightTappedEventHandler;
struct TappedEventHandler;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::UI::Xaml::Input::ManipulationModes> : std::true_type {};
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ICommand>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IContextRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFindNextElementOptions>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManager>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics4>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics5>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics6>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusManagerStatics7>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IFocusMovementResult>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IGettingFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IGettingFocusEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IGettingFocusEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInertiaExpansionBehavior>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInertiaRotationBehavior>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInertiaTranslationBehavior>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInputScope>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInputScopeName>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IInputScopeNameFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyboardAccelerator>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ILosingFocusEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ILosingFocusEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ILosingFocusEventArgs3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationPivot>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationPivotFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IPointer>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IPointerRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IStandardUICommand>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IStandardUICommand2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IStandardUICommandFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IStandardUICommandStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::ITappedRoutedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IXamlUICommand>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IXamlUICommandFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::IXamlUICommandStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::AccessKeyManager>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ContextRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ExecuteRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FindNextElementOptions>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusManager>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusMovementResult>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::GettingFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::HoldingRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::InertiaExpansionBehavior>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::InertiaRotationBehavior>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::InertiaTranslationBehavior>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::InputScope>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::InputScopeName>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyboardAccelerator>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::LosingFocusEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationPivot>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::Pointer>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::PointerRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::RightTappedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::StandardUICommand>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::TappedRoutedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::XamlUICommand>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusInputDeviceKind>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::FocusNavigationDirection>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::InputScopeNameValue>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyTipPlacementMode>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyboardNavigationMode>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationModes>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::StandardUICommandKind>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Input::DoubleTappedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::HoldingEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::KeyEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationStartedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::ManipulationStartingEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::PointerEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::RightTappedEventHandler>{ using type = delegate_category; };
template <> struct category<Windows::UI::Xaml::Input::TappedEventHandler>{ using type = delegate_category; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyDisplayDismissedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyDisplayRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyManager" }; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyManagerStatics" }; };
template <> struct name<Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IAccessKeyManagerStatics2" }; };
template <> struct name<Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ICanExecuteRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ICharacterReceivedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ICommand>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ICommand" }; };
template <> struct name<Windows::UI::Xaml::Input::IContextRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IContextRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IDoubleTappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IExecuteRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IFindNextElementOptions>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFindNextElementOptions" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManager" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerGotFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerLostFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics2" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics3" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics4>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics4" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics5>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics5" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics6>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics6" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusManagerStatics7>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusManagerStatics7" }; };
template <> struct name<Windows::UI::Xaml::Input::IFocusMovementResult>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IFocusMovementResult" }; };
template <> struct name<Windows::UI::Xaml::Input::IGettingFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IGettingFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IGettingFocusEventArgs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IGettingFocusEventArgs2" }; };
template <> struct name<Windows::UI::Xaml::Input::IGettingFocusEventArgs3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IGettingFocusEventArgs3" }; };
template <> struct name<Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IHoldingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IInertiaExpansionBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInertiaExpansionBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::IInertiaRotationBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInertiaRotationBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::IInertiaTranslationBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInertiaTranslationBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::IInputScope>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInputScope" }; };
template <> struct name<Windows::UI::Xaml::Input::IInputScopeName>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInputScopeName" }; };
template <> struct name<Windows::UI::Xaml::Input::IInputScopeNameFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IInputScopeNameFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyRoutedEventArgs2" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyRoutedEventArgs3" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyboardAccelerator>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyboardAccelerator" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyboardAcceleratorFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyboardAcceleratorInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyboardAcceleratorInvokedEventArgs2" }; };
template <> struct name<Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IKeyboardAcceleratorStatics" }; };
template <> struct name<Windows::UI::Xaml::Input::ILosingFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ILosingFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ILosingFocusEventArgs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ILosingFocusEventArgs2" }; };
template <> struct name<Windows::UI::Xaml::Input::ILosingFocusEventArgs3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ILosingFocusEventArgs3" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationCompletedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationDeltaRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationInertiaStartingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationPivot>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationPivot" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationPivotFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationPivotFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationStartedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationStartedRoutedEventArgsFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IManipulationStartingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.INoFocusCandidateFoundEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IPointer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IPointer" }; };
template <> struct name<Windows::UI::Xaml::Input::IPointerRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IPointerRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IPointerRoutedEventArgs2" }; };
template <> struct name<Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IProcessKeyboardAcceleratorEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IRightTappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IStandardUICommand>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IStandardUICommand" }; };
template <> struct name<Windows::UI::Xaml::Input::IStandardUICommand2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IStandardUICommand2" }; };
template <> struct name<Windows::UI::Xaml::Input::IStandardUICommandFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IStandardUICommandFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IStandardUICommandStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IStandardUICommandStatics" }; };
template <> struct name<Windows::UI::Xaml::Input::ITappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ITappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::IXamlUICommand>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IXamlUICommand" }; };
template <> struct name<Windows::UI::Xaml::Input::IXamlUICommandFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IXamlUICommandFactory" }; };
template <> struct name<Windows::UI::Xaml::Input::IXamlUICommandStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.IXamlUICommandStatics" }; };
template <> struct name<Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.AccessKeyDisplayDismissedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.AccessKeyDisplayRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.AccessKeyInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::AccessKeyManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.AccessKeyManager" }; };
template <> struct name<Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.CanExecuteRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.CharacterReceivedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ContextRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ContextRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.DoubleTappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ExecuteRequestedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ExecuteRequestedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::FindNextElementOptions>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FindNextElementOptions" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusManager>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusManager" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusManagerGotFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusManagerLostFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusMovementResult>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusMovementResult" }; };
template <> struct name<Windows::UI::Xaml::Input::GettingFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.GettingFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::HoldingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.HoldingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::InertiaExpansionBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InertiaExpansionBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::InertiaRotationBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InertiaRotationBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::InertiaTranslationBehavior>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InertiaTranslationBehavior" }; };
template <> struct name<Windows::UI::Xaml::Input::InputScope>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InputScope" }; };
template <> struct name<Windows::UI::Xaml::Input::InputScopeName>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InputScopeName" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyboardAccelerator>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyboardAccelerator" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyboardAcceleratorInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::LosingFocusEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.LosingFocusEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationCompletedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationDeltaRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationInertiaStartingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationPivot>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationPivot" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationStartedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationStartingRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.NoFocusCandidateFoundEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::Pointer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.Pointer" }; };
template <> struct name<Windows::UI::Xaml::Input::PointerRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.PointerRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ProcessKeyboardAcceleratorEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::RightTappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.RightTappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::StandardUICommand>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.StandardUICommand" }; };
template <> struct name<Windows::UI::Xaml::Input::TappedRoutedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.TappedRoutedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Input::XamlUICommand>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.XamlUICommand" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusInputDeviceKind>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusInputDeviceKind" }; };
template <> struct name<Windows::UI::Xaml::Input::FocusNavigationDirection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.FocusNavigationDirection" }; };
template <> struct name<Windows::UI::Xaml::Input::InputScopeNameValue>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.InputScopeNameValue" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyTipPlacementMode>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyTipPlacementMode" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyboardAcceleratorPlacementMode" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyboardNavigationMode>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyboardNavigationMode" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationModes>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationModes" }; };
template <> struct name<Windows::UI::Xaml::Input::StandardUICommandKind>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.StandardUICommandKind" }; };
template <> struct name<Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.XYFocusKeyboardNavigationMode" }; };
template <> struct name<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.XYFocusNavigationStrategy" }; };
template <> struct name<Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.XYFocusNavigationStrategyOverride" }; };
template <> struct name<Windows::UI::Xaml::Input::DoubleTappedEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.DoubleTappedEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::HoldingEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.HoldingEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::KeyEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.KeyEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationCompletedEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationDeltaEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationInertiaStartingEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationStartedEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationStartedEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::ManipulationStartingEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.ManipulationStartingEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::PointerEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.PointerEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::RightTappedEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.RightTappedEventHandler" }; };
template <> struct name<Windows::UI::Xaml::Input::TappedEventHandler>{ static constexpr auto & value{ L"Windows.UI.Xaml.Input.TappedEventHandler" }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>{ static constexpr guid value{ 0x8A610DC6,0xD72D,0x4CA8,{ 0x9F,0x66,0x55,0x6F,0x35,0xB5,0x13,0xDA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>{ static constexpr guid value{ 0x0C079E55,0x13FE,0x4D03,{ 0xA6,0x1D,0xE1,0x2F,0x06,0x56,0x72,0x86 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>{ static constexpr guid value{ 0xCFE9CD97,0xC718,0x4091,{ 0xB7,0xDD,0xAD,0xF1,0xC0,0x72,0xB1,0xE1 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyManager>{ static constexpr guid value{ 0xECC973B0,0x2EE9,0x4B1C,{ 0x98,0xD7,0x6E,0x0E,0x81,0x6D,0x33,0x4B } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>{ static constexpr guid value{ 0x4CA0EFE6,0xD9C8,0x4EBC,{ 0xB4,0xC7,0x30,0xD1,0x83,0x8A,0x81,0xF1 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>{ static constexpr guid value{ 0x962BB594,0x2AB3,0x47C5,{ 0x95,0x4B,0x70,0x92,0xF3,0x55,0xF7,0x97 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>{ static constexpr guid value{ 0xC8E75256,0x1950,0x505D,{ 0x99,0x3B,0x75,0x90,0x7E,0xF9,0x68,0x30 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>{ static constexpr guid value{ 0x7849FD82,0x48E4,0x444D,{ 0x94,0x19,0x93,0xAB,0x88,0x92,0xC1,0x07 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ICommand>{ static constexpr guid value{ 0xE5AF3542,0xCA67,0x4081,{ 0x99,0x5B,0x70,0x9D,0xD1,0x37,0x92,0xDF } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IContextRequestedEventArgs>{ static constexpr guid value{ 0x42618E0A,0x1CB6,0x46FB,{ 0x83,0x74,0x0A,0xEC,0x68,0xAA,0x5E,0x51 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>{ static constexpr guid value{ 0xAF404424,0x26DF,0x44F4,{ 0x87,0x14,0x93,0x59,0x24,0x9B,0x62,0xD3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>{ static constexpr guid value{ 0xE07FA734,0xA0B6,0x5755,{ 0x9E,0x87,0x24,0xF5,0x4C,0xCA,0x93,0x72 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFindNextElementOptions>{ static constexpr guid value{ 0xD88AE22B,0x46C2,0x41FC,{ 0x89,0x7E,0xB5,0x96,0x19,0x77,0xB8,0x9D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManager>{ static constexpr guid value{ 0xC843F50B,0x3B83,0x4DA1,{ 0x9D,0x6F,0x55,0x7C,0x11,0x69,0xF3,0x41 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>{ static constexpr guid value{ 0x97AA5D83,0x535B,0x507A,{ 0x86,0x8E,0x62,0xB7,0x06,0xF0,0x6B,0x61 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>{ static constexpr guid value{ 0x3E157E7A,0x9578,0x5CD3,{ 0xAA,0xA8,0x05,0x1B,0x3D,0x39,0x19,0x78 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics>{ static constexpr guid value{ 0x1ECCD326,0x8182,0x4482,{ 0x82,0x6A,0x09,0x18,0xE9,0xED,0x9A,0xF7 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics2>{ static constexpr guid value{ 0xA920D761,0xDD87,0x4F31,{ 0xBE,0xDA,0xEF,0x41,0x7F,0xE7,0xC0,0x4A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics3>{ static constexpr guid value{ 0x60805EBF,0xB149,0x417D,{ 0x83,0xF1,0xBA,0xEB,0x56,0x0E,0x2A,0x47 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics4>{ static constexpr guid value{ 0x29276E9C,0x1C6C,0x414A,{ 0xBA,0x1C,0x96,0xEF,0xD5,0x96,0x2B,0xCD } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics5>{ static constexpr guid value{ 0x280EDC61,0x207A,0x4D7B,{ 0xB9,0x8F,0xCE,0x16,0x5E,0x1B,0x20,0x15 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics6>{ static constexpr guid value{ 0x3546A1B6,0x20BF,0x5007,{ 0x92,0x9D,0xE6,0xD3,0x2E,0x16,0xAF,0xE4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusManagerStatics7>{ static constexpr guid value{ 0x95D6FA97,0xF0FC,0x5C32,{ 0xB2,0x9D,0x07,0xC0,0x4E,0xC9,0x66,0xB0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IFocusMovementResult>{ static constexpr guid value{ 0x06DFEAD3,0xC2AE,0x44BB,{ 0xBF,0xAB,0x9C,0x73,0xDE,0x84,0x07,0xA4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IGettingFocusEventArgs>{ static constexpr guid value{ 0xFA05B9CE,0xC67C,0x4BE8,{ 0x8F,0xD4,0xC4,0x4D,0x67,0x87,0x7E,0x0D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IGettingFocusEventArgs2>{ static constexpr guid value{ 0x88754D7B,0xB4B9,0x4959,{ 0x8B,0xCE,0x89,0xBF,0x21,0x2E,0xD4,0xEB } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IGettingFocusEventArgs3>{ static constexpr guid value{ 0x4E024891,0xDB3F,0x5E78,{ 0xB7,0x5A,0x62,0xBF,0xC3,0x51,0x07,0x35 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>{ static constexpr guid value{ 0xC246FF23,0xD80D,0x44DE,{ 0x8D,0xB9,0x0D,0x81,0x5E,0x26,0x9A,0xC0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInertiaExpansionBehavior>{ static constexpr guid value{ 0x751D87E5,0x8D42,0x44C5,{ 0x96,0x5E,0x3C,0xD3,0x0C,0xC9,0xD6,0xF7 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInertiaRotationBehavior>{ static constexpr guid value{ 0x424CFB2E,0xBBFD,0x4625,{ 0xAE,0x78,0x20,0xC6,0x5B,0xF1,0xEF,0xAF } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInertiaTranslationBehavior>{ static constexpr guid value{ 0x45D3A512,0x3B32,0x4882,{ 0xA4,0xC2,0xEC,0xFA,0x2D,0x4B,0x6D,0xF0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInputScope>{ static constexpr guid value{ 0x5C0F85F3,0xF9D8,0x4220,{ 0xB6,0x66,0x04,0x5D,0x07,0x4D,0x9B,0xFA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInputScopeName>{ static constexpr guid value{ 0xFD3E6997,0x08FB,0x4CBA,{ 0xA0,0x21,0x79,0x2D,0x75,0x89,0xFD,0x5A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IInputScopeNameFactory>{ static constexpr guid value{ 0x4A40BB52,0x4BD7,0x4E54,{ 0x86,0x17,0x1C,0xDA,0x8A,0x1E,0xDA,0x7F } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyRoutedEventArgs>{ static constexpr guid value{ 0xD4CD3DFE,0x4079,0x42E9,{ 0xA3,0x9A,0x30,0x95,0xD3,0xF0,0x49,0xC6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>{ static constexpr guid value{ 0x1B02D57A,0x9634,0x4F14,{ 0x91,0xB2,0x13,0x3E,0x42,0xFD,0xB3,0xCD } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>{ static constexpr guid value{ 0x2779F5B4,0xCA41,0x411B,{ 0xA8,0xEF,0xF4,0xFC,0x78,0xE7,0x80,0x57 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyboardAccelerator>{ static constexpr guid value{ 0x92E6181E,0x19AE,0x465A,{ 0x9B,0x3C,0xA7,0x1E,0xE9,0xEA,0x74,0x20 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>{ static constexpr guid value{ 0x44D88A99,0x4BFD,0x4A47,{ 0xA8,0x93,0x51,0x5F,0x38,0x86,0x23,0xF6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>{ static constexpr guid value{ 0xC00B03F2,0x04E7,0x4415,{ 0xB1,0x7D,0xD7,0x6B,0x94,0x90,0xDE,0x2B } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>{ static constexpr guid value{ 0xBEFCA4B8,0x5907,0x48EE,{ 0x8E,0x21,0x9C,0x96,0x90,0x78,0xFA,0x11 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>{ static constexpr guid value{ 0x3BD43D51,0x9BB3,0x456D,{ 0xBF,0x15,0x80,0x4A,0xDF,0xB8,0x62,0x61 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ILosingFocusEventArgs>{ static constexpr guid value{ 0xF9F683C7,0xD789,0x472B,{ 0xAA,0x93,0x6D,0x41,0x05,0xE6,0xDA,0xBE } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ILosingFocusEventArgs2>{ static constexpr guid value{ 0x0493FAD9,0xC27F,0x469F,{ 0x8E,0x62,0x52,0xB3,0xA4,0xF7,0xCD,0x54 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ILosingFocusEventArgs3>{ static constexpr guid value{ 0xC98900BD,0x0B79,0x566E,{ 0xAD,0x1F,0x43,0x6F,0xA5,0x13,0xAE,0x22 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>{ static constexpr guid value{ 0xB5AD9B23,0x2F41,0x498E,{ 0x83,0x19,0x01,0x5E,0xE8,0xA7,0x53,0x46 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>{ static constexpr guid value{ 0x400D5794,0x4C6F,0x491D,{ 0x82,0xD6,0x35,0x17,0x10,0x93,0x99,0xC6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>{ static constexpr guid value{ 0x246A91A9,0xCA43,0x4C0B,{ 0xAC,0xEF,0x81,0xE8,0xB8,0x14,0x75,0x20 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationPivot>{ static constexpr guid value{ 0x2E3838A5,0xE6C2,0x4998,{ 0x82,0xAC,0x18,0x74,0x8B,0x14,0x16,0x66 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationPivotFactory>{ static constexpr guid value{ 0x6D05B039,0x3702,0x4396,{ 0xAD,0x9B,0xA8,0x25,0xEF,0xA6,0x3A,0x3B } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>{ static constexpr guid value{ 0x5DB1AA05,0x9F80,0x48B6,{ 0xAE,0x6C,0x4F,0x11,0x9D,0xE8,0xFF,0x13 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>{ static constexpr guid value{ 0x84C1DAA7,0x7272,0x4463,{ 0xB6,0xC3,0xA4,0x0B,0x9B,0xA1,0x51,0xFC } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>{ static constexpr guid value{ 0x18D636B7,0x53A4,0x4C15,{ 0xA4,0x98,0xF3,0xA9,0xCA,0x21,0x2A,0x42 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>{ static constexpr guid value{ 0xEC3601A7,0x1007,0x48F9,{ 0xB6,0xB3,0xED,0x0B,0xEA,0x53,0x93,0x7D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IPointer>{ static constexpr guid value{ 0x5EE8F39F,0x747D,0x4171,{ 0x90,0xE6,0xCD,0x37,0xA9,0xDF,0xFB,0x11 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IPointerRoutedEventArgs>{ static constexpr guid value{ 0xDA628F0A,0x9752,0x49E2,{ 0xBD,0xE2,0x49,0xEC,0xCA,0xB9,0x19,0x4D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>{ static constexpr guid value{ 0x0821F294,0x1DE6,0x4711,{ 0xBA,0x7C,0x8D,0x4B,0x8B,0x09,0x11,0xD0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>{ static constexpr guid value{ 0xFB79C216,0x972B,0x440C,{ 0x9B,0x83,0x2B,0x41,0x98,0xDC,0xF0,0x9D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>{ static constexpr guid value{ 0x6834869D,0x7BD5,0x4033,{ 0xB2,0x37,0x17,0x2F,0x79,0xAB,0xE3,0x93 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IStandardUICommand>{ static constexpr guid value{ 0xD2BF7F43,0x0504,0x52D0,{ 0x8A,0xA6,0x0C,0xB0,0xF7,0x56,0xEB,0x27 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IStandardUICommand2>{ static constexpr guid value{ 0xE3666069,0xF9E4,0x51EB,{ 0x88,0x5B,0x7A,0x62,0x0A,0x07,0x82,0xEA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IStandardUICommandFactory>{ static constexpr guid value{ 0x8F1A7590,0xDCE1,0x56E4,{ 0xAB,0x63,0xF5,0xCE,0x3C,0xE4,0xEB,0xF6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IStandardUICommandStatics>{ static constexpr guid value{ 0x7EA87ED9,0x2978,0x5533,{ 0x9B,0x2E,0x67,0x59,0xCE,0x88,0x56,0x9F } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ITappedRoutedEventArgs>{ static constexpr guid value{ 0xA099E6BE,0xE624,0x459A,{ 0xBB,0x1D,0xE0,0x5C,0x73,0xE2,0xCC,0x66 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IXamlUICommand>{ static constexpr guid value{ 0x8494F8D4,0xEAD1,0x5F01,{ 0xAD,0x2E,0xA8,0xCA,0xD4,0xF9,0xDC,0x0E } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IXamlUICommandFactory>{ static constexpr guid value{ 0x1EEC08C3,0xE061,0x5E10,{ 0x9F,0x2A,0x2B,0xAA,0x84,0x08,0x85,0xC2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::IXamlUICommandStatics>{ static constexpr guid value{ 0x66BC457C,0x1A0C,0x58ED,{ 0x87,0x6E,0x71,0x53,0x3F,0x96,0x6D,0xB6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::DoubleTappedEventHandler>{ static constexpr guid value{ 0x3124D025,0x04A7,0x4D45,{ 0x82,0x5E,0x82,0x04,0xA6,0x24,0xDB,0xF4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::HoldingEventHandler>{ static constexpr guid value{ 0xECAE8CCD,0x8E5E,0x4FBE,{ 0x98,0x46,0x30,0xA6,0x37,0x0A,0xFC,0xDF } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::KeyEventHandler>{ static constexpr guid value{ 0x7C63D2E5,0x7A0E,0x4E12,{ 0xB9,0x6A,0x77,0x15,0xAA,0x6F,0xF1,0xC8 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler>{ static constexpr guid value{ 0x38EF4B0F,0x14F8,0x42DF,{ 0x9A,0x1E,0xA4,0xBC,0xC4,0xAF,0x77,0xF4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler>{ static constexpr guid value{ 0xAA1160CB,0xDFB9,0x4C56,{ 0xAB,0xDC,0x71,0x1B,0x63,0xC8,0xEB,0x94 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler>{ static constexpr guid value{ 0xD39D6322,0x7C9C,0x481B,{ 0x82,0x7B,0xC8,0xB2,0xD9,0xBB,0x6F,0xC7 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ManipulationStartedEventHandler>{ static constexpr guid value{ 0xF88345F8,0xE0A3,0x4BE2,{ 0xB9,0x0C,0xDC,0x20,0xE6,0xD8,0xBE,0xB0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::ManipulationStartingEventHandler>{ static constexpr guid value{ 0x10D0B04E,0xBFE4,0x42CB,{ 0x82,0x3C,0x3F,0xEC,0xD8,0x77,0x0E,0xF8 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::PointerEventHandler>{ static constexpr guid value{ 0xE4385929,0xC004,0x4BCF,{ 0x89,0x70,0x35,0x94,0x86,0xE3,0x9F,0x88 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::RightTappedEventHandler>{ static constexpr guid value{ 0x2532A062,0xF447,0x4950,{ 0x9C,0x46,0xF1,0xE3,0x4A,0x2C,0x22,0x38 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Input::TappedEventHandler>{ static constexpr guid value{ 0x68D940CC,0x9FF0,0x49CE,{ 0xB1,0x41,0x3F,0x07,0xEC,0x47,0x7B,0x97 } }; };
template <> struct default_interface<Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs>{ using type = Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs>{ using type = Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs>{ using type = Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::AccessKeyManager>{ using type = Windows::UI::Xaml::Input::IAccessKeyManager; };
template <> struct default_interface<Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs>{ using type = Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ContextRequestedEventArgs>{ using type = Windows::UI::Xaml::Input::IContextRequestedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::DoubleTappedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ExecuteRequestedEventArgs>{ using type = Windows::UI::Xaml::Input::IExecuteRequestedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::FindNextElementOptions>{ using type = Windows::UI::Xaml::Input::IFindNextElementOptions; };
template <> struct default_interface<Windows::UI::Xaml::Input::FocusManager>{ using type = Windows::UI::Xaml::Input::IFocusManager; };
template <> struct default_interface<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs>{ using type = Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs>{ using type = Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::FocusMovementResult>{ using type = Windows::UI::Xaml::Input::IFocusMovementResult; };
template <> struct default_interface<Windows::UI::Xaml::Input::GettingFocusEventArgs>{ using type = Windows::UI::Xaml::Input::IGettingFocusEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::HoldingRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IHoldingRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::InertiaExpansionBehavior>{ using type = Windows::UI::Xaml::Input::IInertiaExpansionBehavior; };
template <> struct default_interface<Windows::UI::Xaml::Input::InertiaRotationBehavior>{ using type = Windows::UI::Xaml::Input::IInertiaRotationBehavior; };
template <> struct default_interface<Windows::UI::Xaml::Input::InertiaTranslationBehavior>{ using type = Windows::UI::Xaml::Input::IInertiaTranslationBehavior; };
template <> struct default_interface<Windows::UI::Xaml::Input::InputScope>{ using type = Windows::UI::Xaml::Input::IInputScope; };
template <> struct default_interface<Windows::UI::Xaml::Input::InputScopeName>{ using type = Windows::UI::Xaml::Input::IInputScopeName; };
template <> struct default_interface<Windows::UI::Xaml::Input::KeyRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IKeyRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::KeyboardAccelerator>{ using type = Windows::UI::Xaml::Input::IKeyboardAccelerator; };
template <> struct default_interface<Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs>{ using type = Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::LosingFocusEventArgs>{ using type = Windows::UI::Xaml::Input::ILosingFocusEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationCompletedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationDeltaRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationInertiaStartingRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationPivot>{ using type = Windows::UI::Xaml::Input::IManipulationPivot; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ManipulationStartingRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs>{ using type = Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::Pointer>{ using type = Windows::UI::Xaml::Input::IPointer; };
template <> struct default_interface<Windows::UI::Xaml::Input::PointerRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IPointerRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs>{ using type = Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::RightTappedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::StandardUICommand>{ using type = Windows::UI::Xaml::Input::IStandardUICommand; };
template <> struct default_interface<Windows::UI::Xaml::Input::TappedRoutedEventArgs>{ using type = Windows::UI::Xaml::Input::ITappedRoutedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Input::XamlUICommand>{ using type = Windows::UI::Xaml::Input::IXamlUICommand; };

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PressedKeys(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyManager>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsDisplayModeEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_IsDisplayModeEnabledChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_IsDisplayModeEnabledChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL ExitDisplayMode() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IAccessKeyManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AreKeyTipsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AreKeyTipsEnabled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parameter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CanExecute(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CanExecute(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Character(char16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ICommand>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_CanExecuteChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CanExecuteChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL CanExecute(void* parameter, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL Execute(void* parameter) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IContextRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetPosition(void* relativeTo, Windows::Foundation::Point* point, bool* returnValue) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IExecuteRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parameter(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFindNextElementOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SearchRoot(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SearchRoot(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExclusionRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExclusionRect(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HintRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HintRect(Windows::Foundation::Rect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManager>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetFocusedElement(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FindNextFocusableElementWithHint(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, Windows::Foundation::Rect hintRect, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryMoveFocusWithOptions(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FindFirstFocusableElement(void* searchScope, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FindLastFocusableElement(void* searchScope, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FindNextElementWithOptions(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryFocusAsync(void* element, Windows::UI::Xaml::FocusState value, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryMoveFocusWithOptionsAsync(Windows::UI::Xaml::Input::FocusNavigationDirection focusNavigationDirection, void* focusNavigationOptions, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics6>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GettingFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GettingFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_LosingFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LosingFocus(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusManagerStatics7>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetFocusedElement(void* xamlRoot, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IFocusMovementResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IGettingFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NewFocusedElement(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cancel(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Cancel(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IGettingFocusEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryCancel(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetNewFocusedElement(void* element, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IGettingFocusEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IHoldingRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HoldingState(Windows::UI::Input::HoldingState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInertiaExpansionBehavior>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredExpansion(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredExpansion(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInertiaRotationBehavior>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredRotation(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredRotation(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInertiaTranslationBehavior>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesiredDeceleration(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredDeceleration(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredDisplacement(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DesiredDisplacement(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInputScope>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Names(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInputScopeName>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NameValue(Windows::UI::Xaml::Input::InputScopeNameValue* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NameValue(Windows::UI::Xaml::Input::InputScopeNameValue value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IInputScopeNameFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Input::InputScopeNameValue nameValue, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyRoutedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OriginalKey(Windows::System::VirtualKey* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyRoutedEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyboardAccelerator>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Key(Windows::System::VirtualKey value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Modifiers(Windows::System::VirtualKeyModifiers* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Modifiers(Windows::System::VirtualKeyModifiers value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScopeOwner(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScopeOwner(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Invoked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Invoked(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Element(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_KeyboardAccelerator(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_KeyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModifiersProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabledProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScopeOwnerProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ILosingFocusEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NewFocusedElement(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NewFocusedElement(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cancel(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Cancel(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ILosingFocusEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryCancel(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetNewFocusedElement(void* element, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ILosingFocusEventArgs3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInertial(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInertial(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpansionBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExpansionBehavior(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RotationBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RotationBehavior(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TranslationBehavior(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TranslationBehavior(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Delta(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Velocities(struct struct_Windows_UI_Input_ManipulationVelocities* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationPivot>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Center(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Center(Windows::Foundation::Point value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Radius(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Radius(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationPivotFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstanceWithCenterAndRadius(Windows::Foundation::Point center, double radius, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cumulative(struct struct_Windows_UI_Input_ManipulationDelta* value) noexcept = 0;
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Mode(Windows::UI::Xaml::Input::ManipulationModes* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Mode(Windows::UI::Xaml::Input::ManipulationModes value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Container(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pivot(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Pivot(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Direction(Windows::UI::Xaml::Input::FocusNavigationDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputDevice(Windows::UI::Xaml::Input::FocusInputDeviceKind* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IPointer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PointerId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInContact(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInRange(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IPointerRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Pointer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentPoint(void* relativeTo, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetIntermediatePoints(void* relativeTo, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IPointerRoutedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsGenerated(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Key(Windows::System::VirtualKey* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Modifiers(Windows::System::VirtualKeyModifiers* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IStandardUICommand>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Kind(Windows::UI::Xaml::Input::StandardUICommandKind* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IStandardUICommand2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Kind(Windows::UI::Xaml::Input::StandardUICommandKind value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IStandardUICommandFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateInstanceWithKind(Windows::UI::Xaml::Input::StandardUICommandKind kind, void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IStandardUICommandStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_KindProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ITappedRoutedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IXamlUICommand>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Label(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Label(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IconSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IconSource(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyboardAccelerators(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKey(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AccessKey(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Description(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Command(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Command(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ExecuteRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ExecuteRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_CanExecuteRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CanExecuteRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL NotifyCanExecuteChanged() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IXamlUICommandFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::IXamlUICommandStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LabelProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IconSourceProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyboardAcceleratorsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKeyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DescriptionProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CommandProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::DoubleTappedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::HoldingEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::KeyEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ManipulationStartedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::ManipulationStartingEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::PointerEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::RightTappedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Input::TappedEventHandler>{ struct type : IUnknown
{
    virtual int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyDisplayDismissedEventArgs
{
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyDisplayDismissedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyDisplayDismissedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyDisplayRequestedEventArgs
{
    hstring PressedKeys() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyDisplayRequestedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyDisplayRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyInvokedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyInvokedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyManager
{
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyManager> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyManager<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics
{
    bool IsDisplayModeEnabled() const;
    winrt::event_token IsDisplayModeEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler) const;
    using IsDisplayModeEnabledChanged_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IAccessKeyManagerStatics, &impl::abi_t<Windows::UI::Xaml::Input::IAccessKeyManagerStatics>::remove_IsDisplayModeEnabledChanged>;
    IsDisplayModeEnabledChanged_revoker IsDisplayModeEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> const& handler) const;
    void IsDisplayModeEnabledChanged(winrt::event_token const& token) const noexcept;
    void ExitDisplayMode() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyManagerStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2
{
    bool AreKeyTipsEnabled() const;
    void AreKeyTipsEnabled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IAccessKeyManagerStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IAccessKeyManagerStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs
{
    Windows::Foundation::IInspectable Parameter() const;
    bool CanExecute() const;
    void CanExecute(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ICanExecuteRequestedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ICanExecuteRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs
{
    char16_t Character() const;
    Windows::UI::Core::CorePhysicalKeyStatus KeyStatus() const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ICharacterReceivedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ICharacterReceivedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ICommand
{
    winrt::event_token CanExecuteChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using CanExecuteChanged_revoker = impl::event_revoker<Windows::UI::Xaml::Input::ICommand, &impl::abi_t<Windows::UI::Xaml::Input::ICommand>::remove_CanExecuteChanged>;
    CanExecuteChanged_revoker CanExecuteChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void CanExecuteChanged(winrt::event_token const& token) const noexcept;
    bool CanExecute(Windows::Foundation::IInspectable const& parameter) const;
    void Execute(Windows::Foundation::IInspectable const& parameter) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ICommand> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ICommand<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    bool TryGetPosition(Windows::UI::Xaml::UIElement const& relativeTo, Windows::Foundation::Point& point) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IContextRequestedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IContextRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs
{
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Point GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IDoubleTappedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IDoubleTappedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IExecuteRequestedEventArgs
{
    Windows::Foundation::IInspectable Parameter() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IExecuteRequestedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IExecuteRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFindNextElementOptions
{
    Windows::UI::Xaml::DependencyObject SearchRoot() const;
    void SearchRoot(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::Foundation::Rect ExclusionRect() const;
    void ExclusionRect(Windows::Foundation::Rect const& value) const;
    Windows::Foundation::Rect HintRect() const;
    void HintRect(Windows::Foundation::Rect const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride XYFocusNavigationStrategyOverride() const;
    void XYFocusNavigationStrategyOverride(Windows::UI::Xaml::Input::XYFocusNavigationStrategyOverride const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFindNextElementOptions> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFindNextElementOptions<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManager
{
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManager> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManager<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs
{
    Windows::UI::Xaml::DependencyObject NewFocusedElement() const;
    winrt::guid CorrelationId() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerGotFocusEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerGotFocusEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs
{
    Windows::UI::Xaml::DependencyObject OldFocusedElement() const;
    winrt::guid CorrelationId() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerLostFocusEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerLostFocusEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics
{
    Windows::Foundation::IInspectable GetFocusedElement() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics2
{
    bool TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics3
{
    Windows::UI::Xaml::UIElement FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const;
    Windows::UI::Xaml::UIElement FindNextFocusableElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::Foundation::Rect const& hintRect) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics3> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics4
{
    bool TryMoveFocus(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const;
    Windows::UI::Xaml::DependencyObject FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const;
    Windows::UI::Xaml::DependencyObject FindFirstFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope) const;
    Windows::UI::Xaml::DependencyObject FindLastFocusableElement(Windows::UI::Xaml::DependencyObject const& searchScope) const;
    Windows::UI::Xaml::DependencyObject FindNextElement(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics4> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics4<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics5
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryFocusAsync(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FocusState const& value) const;
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection) const;
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Input::FocusMovementResult> TryMoveFocusAsync(Windows::UI::Xaml::Input::FocusNavigationDirection const& focusNavigationDirection, Windows::UI::Xaml::Input::FindNextElementOptions const& focusNavigationOptions) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics5> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics5<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics6
{
    winrt::event_token GotFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const;
    using GotFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_GotFocus>;
    GotFocus_revoker GotFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerGotFocusEventArgs> const& handler) const;
    void GotFocus(winrt::event_token const& token) const noexcept;
    winrt::event_token LostFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const;
    using LostFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_LostFocus>;
    LostFocus_revoker LostFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::FocusManagerLostFocusEventArgs> const& handler) const;
    void LostFocus(winrt::event_token const& token) const noexcept;
    winrt::event_token GettingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const;
    using GettingFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_GettingFocus>;
    GettingFocus_revoker GettingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const;
    void GettingFocus(winrt::event_token const& token) const noexcept;
    winrt::event_token LosingFocus(Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const;
    using LosingFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IFocusManagerStatics6, &impl::abi_t<Windows::UI::Xaml::Input::IFocusManagerStatics6>::remove_LosingFocus>;
    LosingFocus_revoker LosingFocus(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const;
    void LosingFocus(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics6> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics6<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusManagerStatics7
{
    Windows::Foundation::IInspectable GetFocusedElement(Windows::UI::Xaml::XamlRoot const& xamlRoot) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusManagerStatics7> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusManagerStatics7<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IFocusMovementResult
{
    bool Succeeded() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IFocusMovementResult> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IFocusMovementResult<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs
{
    Windows::UI::Xaml::DependencyObject OldFocusedElement() const;
    Windows::UI::Xaml::DependencyObject NewFocusedElement() const;
    void NewFocusedElement(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::FocusState FocusState() const;
    Windows::UI::Xaml::Input::FocusNavigationDirection Direction() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::UI::Xaml::Input::FocusInputDeviceKind InputDevice() const;
    bool Cancel() const;
    void Cancel(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IGettingFocusEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2
{
    bool TryCancel() const;
    bool TrySetNewFocusedElement(Windows::UI::Xaml::DependencyObject const& element) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IGettingFocusEventArgs2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs3
{
    winrt::guid CorrelationId() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IGettingFocusEventArgs3> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IGettingFocusEventArgs3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs
{
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    Windows::UI::Input::HoldingState HoldingState() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Point GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IHoldingRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IHoldingRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior
{
    double DesiredDeceleration() const;
    void DesiredDeceleration(double value) const;
    double DesiredExpansion() const;
    void DesiredExpansion(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInertiaExpansionBehavior> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInertiaExpansionBehavior<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior
{
    double DesiredDeceleration() const;
    void DesiredDeceleration(double value) const;
    double DesiredRotation() const;
    void DesiredRotation(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInertiaRotationBehavior> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInertiaRotationBehavior<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior
{
    double DesiredDeceleration() const;
    void DesiredDeceleration(double value) const;
    double DesiredDisplacement() const;
    void DesiredDisplacement(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInertiaTranslationBehavior> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInertiaTranslationBehavior<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInputScope
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::InputScopeName> Names() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInputScope> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInputScope<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInputScopeName
{
    Windows::UI::Xaml::Input::InputScopeNameValue NameValue() const;
    void NameValue(Windows::UI::Xaml::Input::InputScopeNameValue const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInputScopeName> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInputScopeName<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IInputScopeNameFactory
{
    Windows::UI::Xaml::Input::InputScopeName CreateInstance(Windows::UI::Xaml::Input::InputScopeNameValue const& nameValue) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IInputScopeNameFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IInputScopeNameFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs
{
    Windows::System::VirtualKey Key() const;
    Windows::UI::Core::CorePhysicalKeyStatus KeyStatus() const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs2
{
    Windows::System::VirtualKey OriginalKey() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyRoutedEventArgs2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs3
{
    hstring DeviceId() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyRoutedEventArgs3> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyRoutedEventArgs3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyboardAccelerator
{
    Windows::System::VirtualKey Key() const;
    void Key(Windows::System::VirtualKey const& value) const;
    Windows::System::VirtualKeyModifiers Modifiers() const;
    void Modifiers(Windows::System::VirtualKeyModifiers const& value) const;
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    Windows::UI::Xaml::DependencyObject ScopeOwner() const;
    void ScopeOwner(Windows::UI::Xaml::DependencyObject const& value) const;
    winrt::event_token Invoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const;
    using Invoked_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IKeyboardAccelerator, &impl::abi_t<Windows::UI::Xaml::Input::IKeyboardAccelerator>::remove_Invoked>;
    Invoked_revoker Invoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::KeyboardAccelerator, Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs> const& handler) const;
    void Invoked(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyboardAccelerator> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyboardAccelerator<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorFactory
{
    Windows::UI::Xaml::Input::KeyboardAccelerator CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyboardAcceleratorFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs
{
    bool Handled() const;
    void Handled(bool value) const;
    Windows::UI::Xaml::DependencyObject Element() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs2
{
    Windows::UI::Xaml::Input::KeyboardAccelerator KeyboardAccelerator() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyboardAcceleratorInvokedEventArgs2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorInvokedEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics
{
    Windows::UI::Xaml::DependencyProperty KeyProperty() const;
    Windows::UI::Xaml::DependencyProperty ModifiersProperty() const;
    Windows::UI::Xaml::DependencyProperty IsEnabledProperty() const;
    Windows::UI::Xaml::DependencyProperty ScopeOwnerProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IKeyboardAcceleratorStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IKeyboardAcceleratorStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs
{
    Windows::UI::Xaml::DependencyObject OldFocusedElement() const;
    Windows::UI::Xaml::DependencyObject NewFocusedElement() const;
    void NewFocusedElement(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::FocusState FocusState() const;
    Windows::UI::Xaml::Input::FocusNavigationDirection Direction() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::UI::Xaml::Input::FocusInputDeviceKind InputDevice() const;
    bool Cancel() const;
    void Cancel(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ILosingFocusEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2
{
    bool TryCancel() const;
    bool TrySetNewFocusedElement(Windows::UI::Xaml::DependencyObject const& element) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ILosingFocusEventArgs2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs3
{
    winrt::guid CorrelationId() const;
};
template <> struct consume<Windows::UI::Xaml::Input::ILosingFocusEventArgs3> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ILosingFocusEventArgs3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs
{
    Windows::UI::Xaml::UIElement Container() const;
    Windows::Foundation::Point Position() const;
    bool IsInertial() const;
    Windows::UI::Input::ManipulationDelta Cumulative() const;
    Windows::UI::Input::ManipulationVelocities Velocities() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationCompletedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationCompletedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs
{
    Windows::UI::Xaml::UIElement Container() const;
    Windows::Foundation::Point Position() const;
    bool IsInertial() const;
    Windows::UI::Input::ManipulationDelta Delta() const;
    Windows::UI::Input::ManipulationDelta Cumulative() const;
    Windows::UI::Input::ManipulationVelocities Velocities() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    void Complete() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationDeltaRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationDeltaRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs
{
    Windows::UI::Xaml::UIElement Container() const;
    Windows::UI::Xaml::Input::InertiaExpansionBehavior ExpansionBehavior() const;
    void ExpansionBehavior(Windows::UI::Xaml::Input::InertiaExpansionBehavior const& value) const;
    Windows::UI::Xaml::Input::InertiaRotationBehavior RotationBehavior() const;
    void RotationBehavior(Windows::UI::Xaml::Input::InertiaRotationBehavior const& value) const;
    Windows::UI::Xaml::Input::InertiaTranslationBehavior TranslationBehavior() const;
    void TranslationBehavior(Windows::UI::Xaml::Input::InertiaTranslationBehavior const& value) const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    Windows::UI::Input::ManipulationDelta Delta() const;
    Windows::UI::Input::ManipulationDelta Cumulative() const;
    Windows::UI::Input::ManipulationVelocities Velocities() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationInertiaStartingRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationInertiaStartingRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationPivot
{
    Windows::Foundation::Point Center() const;
    void Center(Windows::Foundation::Point const& value) const;
    double Radius() const;
    void Radius(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationPivot> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationPivot<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationPivotFactory
{
    Windows::UI::Xaml::Input::ManipulationPivot CreateInstanceWithCenterAndRadius(Windows::Foundation::Point const& center, double radius) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationPivotFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationPivotFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs
{
    Windows::UI::Xaml::UIElement Container() const;
    Windows::Foundation::Point Position() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    Windows::UI::Input::ManipulationDelta Cumulative() const;
    void Complete() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgsFactory
{
    Windows::UI::Xaml::Input::ManipulationStartedRoutedEventArgs CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationStartedRoutedEventArgsFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationStartedRoutedEventArgsFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs
{
    Windows::UI::Xaml::Input::ManipulationModes Mode() const;
    void Mode(Windows::UI::Xaml::Input::ManipulationModes const& value) const;
    Windows::UI::Xaml::UIElement Container() const;
    void Container(Windows::UI::Xaml::UIElement const& value) const;
    Windows::UI::Xaml::Input::ManipulationPivot Pivot() const;
    void Pivot(Windows::UI::Xaml::Input::ManipulationPivot const& value) const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IManipulationStartingRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IManipulationStartingRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs
{
    Windows::UI::Xaml::Input::FocusNavigationDirection Direction() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::UI::Xaml::Input::FocusInputDeviceKind InputDevice() const;
};
template <> struct consume<Windows::UI::Xaml::Input::INoFocusCandidateFoundEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_INoFocusCandidateFoundEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IPointer
{
    uint32_t PointerId() const;
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    bool IsInContact() const;
    bool IsInRange() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IPointer> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IPointer<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs
{
    Windows::UI::Xaml::Input::Pointer Pointer() const;
    Windows::System::VirtualKeyModifiers KeyModifiers() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::UI::Input::PointerPoint GetCurrentPoint(Windows::UI::Xaml::UIElement const& relativeTo) const;
    Windows::Foundation::Collections::IVector<Windows::UI::Input::PointerPoint> GetIntermediatePoints(Windows::UI::Xaml::UIElement const& relativeTo) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IPointerRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs2
{
    bool IsGenerated() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IPointerRoutedEventArgs2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IPointerRoutedEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs
{
    Windows::System::VirtualKey Key() const;
    Windows::System::VirtualKeyModifiers Modifiers() const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IProcessKeyboardAcceleratorEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IProcessKeyboardAcceleratorEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs
{
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Point GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IRightTappedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IRightTappedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IStandardUICommand
{
    Windows::UI::Xaml::Input::StandardUICommandKind Kind() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IStandardUICommand> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IStandardUICommand<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IStandardUICommand2
{
    void Kind(Windows::UI::Xaml::Input::StandardUICommandKind const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IStandardUICommand2> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IStandardUICommand2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IStandardUICommandFactory
{
    Windows::UI::Xaml::Input::StandardUICommand CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
    Windows::UI::Xaml::Input::StandardUICommand CreateInstanceWithKind(Windows::UI::Xaml::Input::StandardUICommandKind const& kind, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IStandardUICommandFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IStandardUICommandFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IStandardUICommandStatics
{
    Windows::UI::Xaml::DependencyProperty KindProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IStandardUICommandStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IStandardUICommandStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs
{
    Windows::Devices::Input::PointerDeviceType PointerDeviceType() const;
    bool Handled() const;
    void Handled(bool value) const;
    Windows::Foundation::Point GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const;
};
template <> struct consume<Windows::UI::Xaml::Input::ITappedRoutedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Input_ITappedRoutedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IXamlUICommand
{
    hstring Label() const;
    void Label(param::hstring const& value) const;
    Windows::UI::Xaml::Controls::IconSource IconSource() const;
    void IconSource(Windows::UI::Xaml::Controls::IconSource const& value) const;
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator> KeyboardAccelerators() const;
    hstring AccessKey() const;
    void AccessKey(param::hstring const& value) const;
    hstring Description() const;
    void Description(param::hstring const& value) const;
    Windows::UI::Xaml::Input::ICommand Command() const;
    void Command(Windows::UI::Xaml::Input::ICommand const& value) const;
    winrt::event_token ExecuteRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const;
    using ExecuteRequested_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IXamlUICommand, &impl::abi_t<Windows::UI::Xaml::Input::IXamlUICommand>::remove_ExecuteRequested>;
    ExecuteRequested_revoker ExecuteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::ExecuteRequestedEventArgs> const& handler) const;
    void ExecuteRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token CanExecuteRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const;
    using CanExecuteRequested_revoker = impl::event_revoker<Windows::UI::Xaml::Input::IXamlUICommand, &impl::abi_t<Windows::UI::Xaml::Input::IXamlUICommand>::remove_CanExecuteRequested>;
    CanExecuteRequested_revoker CanExecuteRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Input::XamlUICommand, Windows::UI::Xaml::Input::CanExecuteRequestedEventArgs> const& handler) const;
    void CanExecuteRequested(winrt::event_token const& token) const noexcept;
    void NotifyCanExecuteChanged() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IXamlUICommand> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IXamlUICommand<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IXamlUICommandFactory
{
    Windows::UI::Xaml::Input::XamlUICommand CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Input::IXamlUICommandFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IXamlUICommandFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Input_IXamlUICommandStatics
{
    Windows::UI::Xaml::DependencyProperty LabelProperty() const;
    Windows::UI::Xaml::DependencyProperty IconSourceProperty() const;
    Windows::UI::Xaml::DependencyProperty KeyboardAcceleratorsProperty() const;
    Windows::UI::Xaml::DependencyProperty AccessKeyProperty() const;
    Windows::UI::Xaml::DependencyProperty DescriptionProperty() const;
    Windows::UI::Xaml::DependencyProperty CommandProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Input::IXamlUICommandStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Input_IXamlUICommandStatics<D>; };

}
