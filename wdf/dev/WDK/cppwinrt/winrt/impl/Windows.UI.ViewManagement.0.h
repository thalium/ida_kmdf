// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration {

struct DeviceInformation;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;
struct UIContext;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

struct ICoreWindow;

}

WINRT_EXPORT namespace winrt::Windows::UI::Popups {

enum class Placement;

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct DisplayRegion;
struct WindowingEnvironment;

}

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement {

enum class ApplicationViewBoundsMode : int32_t
{
    UseVisible = 0,
    UseCoreWindow = 1,
};

enum class ApplicationViewMode : int32_t
{
    Default = 0,
    CompactOverlay = 1,
};

enum class ApplicationViewOrientation : int32_t
{
    Landscape = 0,
    Portrait = 1,
};

enum class ApplicationViewState : int32_t
{
    FullScreenLandscape = 0,
    Filled = 1,
    Snapped = 2,
    FullScreenPortrait = 3,
};

enum class ApplicationViewSwitchingOptions : uint32_t
{
    Default = 0x0,
    SkipAnimation = 0x1,
    ConsolidateViews = 0x2,
};

enum class ApplicationViewWindowingMode : int32_t
{
    Auto = 0,
    PreferredLaunchViewSize = 1,
    FullScreen = 2,
    CompactOverlay = 3,
    Maximized = 4,
};

enum class FullScreenSystemOverlayMode : int32_t
{
    Standard = 0,
    Minimal = 1,
};

enum class HandPreference : int32_t
{
    LeftHanded = 0,
    RightHanded = 1,
};

enum class UIColorType : int32_t
{
    Background = 0,
    Foreground = 1,
    AccentDark3 = 2,
    AccentDark2 = 3,
    AccentDark1 = 4,
    Accent = 5,
    AccentLight1 = 6,
    AccentLight2 = 7,
    AccentLight3 = 8,
    Complement = 9,
};

enum class UIElementType : int32_t
{
    ActiveCaption = 0,
    Background = 1,
    ButtonFace = 2,
    ButtonText = 3,
    CaptionText = 4,
    GrayText = 5,
    Highlight = 6,
    HighlightText = 7,
    Hotlight = 8,
    InactiveCaption = 9,
    InactiveCaptionText = 10,
    Window = 11,
    WindowText = 12,
    AccentColor = 1000,
    TextHigh = 1001,
    TextMedium = 1002,
    TextLow = 1003,
    TextContrastWithHigh = 1004,
    NonTextHigh = 1005,
    NonTextMediumHigh = 1006,
    NonTextMedium = 1007,
    NonTextMediumLow = 1008,
    NonTextLow = 1009,
    PageBackground = 1010,
    PopupBackground = 1011,
    OverlayOutsidePopup = 1012,
};

enum class UserInteractionMode : int32_t
{
    Mouse = 0,
    Touch = 1,
};

enum class ViewSizePreference : int32_t
{
    Default = 0,
    UseLess = 1,
    UseHalf = 2,
    UseMore = 3,
    UseMinimum = 4,
    UseNone = 5,
    Custom = 6,
};

struct IAccessibilitySettings;
struct IActivationViewSwitcher;
struct IApplicationView;
struct IApplicationView2;
struct IApplicationView3;
struct IApplicationView4;
struct IApplicationView7;
struct IApplicationView9;
struct IApplicationViewConsolidatedEventArgs;
struct IApplicationViewConsolidatedEventArgs2;
struct IApplicationViewFullscreenStatics;
struct IApplicationViewInteropStatics;
struct IApplicationViewScaling;
struct IApplicationViewScalingStatics;
struct IApplicationViewStatics;
struct IApplicationViewStatics2;
struct IApplicationViewStatics3;
struct IApplicationViewStatics4;
struct IApplicationViewSwitcherStatics;
struct IApplicationViewSwitcherStatics2;
struct IApplicationViewSwitcherStatics3;
struct IApplicationViewTitleBar;
struct IApplicationViewTransferContext;
struct IApplicationViewTransferContextStatics;
struct IApplicationViewWithContext;
struct IInputPane;
struct IInputPane2;
struct IInputPaneControl;
struct IInputPaneStatics;
struct IInputPaneStatics2;
struct IInputPaneVisibilityEventArgs;
struct IProjectionManagerStatics;
struct IProjectionManagerStatics2;
struct IStatusBar;
struct IStatusBarProgressIndicator;
struct IStatusBarStatics;
struct IUISettings;
struct IUISettings2;
struct IUISettings3;
struct IUISettings4;
struct IUISettings5;
struct IUISettingsAutoHideScrollBarsChangedEventArgs;
struct IUIViewSettings;
struct IUIViewSettingsStatics;
struct IViewModePreferences;
struct IViewModePreferencesStatics;
struct AccessibilitySettings;
struct ActivationViewSwitcher;
struct ApplicationView;
struct ApplicationViewConsolidatedEventArgs;
struct ApplicationViewScaling;
struct ApplicationViewSwitcher;
struct ApplicationViewTitleBar;
struct ApplicationViewTransferContext;
struct InputPane;
struct InputPaneVisibilityEventArgs;
struct ProjectionManager;
struct StatusBar;
struct StatusBarProgressIndicator;
struct UISettings;
struct UISettingsAutoHideScrollBarsChangedEventArgs;
struct UIViewSettings;
struct ViewModePreferences;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::UI::ViewManagement::ApplicationViewSwitchingOptions> : std::true_type {};
template <> struct category<Windows::UI::ViewManagement::IAccessibilitySettings>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IActivationViewSwitcher>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView3>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView4>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView7>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationView9>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewScaling>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewStatics4>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewTitleBar>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewTransferContext>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IApplicationViewWithContext>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPane>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPane2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPaneControl>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPaneStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPaneStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IProjectionManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IProjectionManagerStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IStatusBar>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IStatusBarStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettings>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettings2>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettings3>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettings4>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettings5>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUIViewSettings>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IUIViewSettingsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IViewModePreferences>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::IViewModePreferencesStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::ViewManagement::AccessibilitySettings>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ActivationViewSwitcher>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationView>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewScaling>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewSwitcher>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewTitleBar>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewTransferContext>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::InputPane>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::InputPaneVisibilityEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ProjectionManager>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::StatusBar>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::StatusBarProgressIndicator>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::UISettings>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::UIViewSettings>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ViewModePreferences>{ using type = class_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewBoundsMode>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewMode>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewOrientation>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewState>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewSwitchingOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ApplicationViewWindowingMode>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::FullScreenSystemOverlayMode>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::HandPreference>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::UIColorType>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::UIElementType>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::UserInteractionMode>{ using type = enum_category; };
template <> struct category<Windows::UI::ViewManagement::ViewSizePreference>{ using type = enum_category; };
template <> struct name<Windows::UI::ViewManagement::IAccessibilitySettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IAccessibilitySettings" }; };
template <> struct name<Windows::UI::ViewManagement::IActivationViewSwitcher>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IActivationViewSwitcher" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView2" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView3>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView3" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView4>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView4" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView7>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView7" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationView9>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationView9" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewConsolidatedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewConsolidatedEventArgs2" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewFullscreenStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewInteropStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewScaling>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewScaling" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewScalingStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewStatics2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewStatics2" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewStatics3>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewStatics3" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewStatics4>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewStatics4" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics2" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics3" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewTitleBar>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewTitleBar" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewTransferContext>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewTransferContext" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewTransferContextStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IApplicationViewWithContext>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IApplicationViewWithContext" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPane>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPane" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPane2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPane2" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPaneControl>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPaneControl" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPaneStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPaneStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPaneStatics2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPaneStatics2" }; };
template <> struct name<Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IInputPaneVisibilityEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::IProjectionManagerStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IProjectionManagerStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IProjectionManagerStatics2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IProjectionManagerStatics2" }; };
template <> struct name<Windows::UI::ViewManagement::IStatusBar>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IStatusBar" }; };
template <> struct name<Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IStatusBarProgressIndicator" }; };
template <> struct name<Windows::UI::ViewManagement::IStatusBarStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IStatusBarStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettings" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettings2>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettings2" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettings3>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettings3" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettings4>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettings4" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettings5>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettings5" }; };
template <> struct name<Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUISettingsAutoHideScrollBarsChangedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::IUIViewSettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUIViewSettings" }; };
template <> struct name<Windows::UI::ViewManagement::IUIViewSettingsStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IUIViewSettingsStatics" }; };
template <> struct name<Windows::UI::ViewManagement::IViewModePreferences>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IViewModePreferences" }; };
template <> struct name<Windows::UI::ViewManagement::IViewModePreferencesStatics>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.IViewModePreferencesStatics" }; };
template <> struct name<Windows::UI::ViewManagement::AccessibilitySettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.AccessibilitySettings" }; };
template <> struct name<Windows::UI::ViewManagement::ActivationViewSwitcher>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ActivationViewSwitcher" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationView>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationView" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewConsolidatedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewScaling>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewScaling" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewSwitcher>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewSwitcher" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewTitleBar>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewTitleBar" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewTransferContext>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewTransferContext" }; };
template <> struct name<Windows::UI::ViewManagement::InputPane>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.InputPane" }; };
template <> struct name<Windows::UI::ViewManagement::InputPaneVisibilityEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.InputPaneVisibilityEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::ProjectionManager>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ProjectionManager" }; };
template <> struct name<Windows::UI::ViewManagement::StatusBar>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.StatusBar" }; };
template <> struct name<Windows::UI::ViewManagement::StatusBarProgressIndicator>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.StatusBarProgressIndicator" }; };
template <> struct name<Windows::UI::ViewManagement::UISettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UISettings" }; };
template <> struct name<Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UISettingsAutoHideScrollBarsChangedEventArgs" }; };
template <> struct name<Windows::UI::ViewManagement::UIViewSettings>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UIViewSettings" }; };
template <> struct name<Windows::UI::ViewManagement::ViewModePreferences>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ViewModePreferences" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewBoundsMode>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewBoundsMode" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewMode>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewMode" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewOrientation>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewOrientation" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewState>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewState" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewSwitchingOptions>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewSwitchingOptions" }; };
template <> struct name<Windows::UI::ViewManagement::ApplicationViewWindowingMode>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ApplicationViewWindowingMode" }; };
template <> struct name<Windows::UI::ViewManagement::FullScreenSystemOverlayMode>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.FullScreenSystemOverlayMode" }; };
template <> struct name<Windows::UI::ViewManagement::HandPreference>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.HandPreference" }; };
template <> struct name<Windows::UI::ViewManagement::UIColorType>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UIColorType" }; };
template <> struct name<Windows::UI::ViewManagement::UIElementType>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UIElementType" }; };
template <> struct name<Windows::UI::ViewManagement::UserInteractionMode>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.UserInteractionMode" }; };
template <> struct name<Windows::UI::ViewManagement::ViewSizePreference>{ static constexpr auto & value{ L"Windows.UI.ViewManagement.ViewSizePreference" }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IAccessibilitySettings>{ static constexpr guid value{ 0xFE0E8147,0xC4C0,0x4562,{ 0xB9,0x62,0x13,0x27,0xB5,0x2A,0xD5,0xB9 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IActivationViewSwitcher>{ static constexpr guid value{ 0xDCA71BB6,0x7350,0x492B,{ 0xAA,0xC7,0xC8,0xA1,0x3D,0x72,0x24,0xAD } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView>{ static constexpr guid value{ 0xD222D519,0x4361,0x451E,{ 0x96,0xC4,0x60,0xF4,0xF9,0x74,0x2D,0xB0 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView2>{ static constexpr guid value{ 0xE876B196,0xA545,0x40DC,{ 0xB5,0x94,0x45,0x0C,0xBA,0x68,0xCC,0x00 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView3>{ static constexpr guid value{ 0x903C9CE5,0x793A,0x4FDF,{ 0xA2,0xB2,0xAF,0x1A,0xC2,0x1E,0x31,0x08 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView4>{ static constexpr guid value{ 0x15E5CBEC,0x9E0F,0x46B5,{ 0xBC,0x3F,0x9B,0xF6,0x53,0xE7,0x4B,0x5E } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView7>{ static constexpr guid value{ 0xA0369647,0x5FAF,0x5AA6,{ 0x9C,0x38,0xBE,0xFB,0xB1,0x2A,0x07,0x1E } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationView9>{ static constexpr guid value{ 0x9C6516F9,0x021A,0x5F01,{ 0x93,0xE5,0x9B,0xDA,0xD2,0x64,0x75,0x74 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ static constexpr guid value{ 0x514449EC,0x7EA2,0x4DE7,{ 0xA6,0xA6,0x7D,0xFB,0xAA,0xEB,0xB6,0xFB } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ static constexpr guid value{ 0x1C199ECC,0x6DC1,0x40F4,{ 0xAF,0xEE,0x07,0xD9,0xEA,0x29,0x64,0x30 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ static constexpr guid value{ 0xBC792EBD,0x64FE,0x4B65,{ 0xA0,0xC0,0x90,0x1C,0xE2,0xB6,0x86,0x36 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ static constexpr guid value{ 0xC446FB5D,0x4793,0x4896,{ 0xA8,0xE2,0xBE,0x57,0xA8,0xBB,0x0F,0x50 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewScaling>{ static constexpr guid value{ 0x1D0DDC23,0x23F3,0x4B2D,{ 0x84,0xFE,0x74,0xBF,0x37,0xB4,0x8B,0x66 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ static constexpr guid value{ 0xB08FECF0,0xB946,0x45C8,{ 0xA5,0xE3,0x71,0xF5,0xAA,0x78,0xF8,0x61 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewStatics>{ static constexpr guid value{ 0x010A6306,0xC433,0x44E5,{ 0xA9,0xF2,0xBD,0x84,0xD4,0x03,0x0A,0x95 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewStatics2>{ static constexpr guid value{ 0xAF338AE5,0xCF64,0x423C,{ 0x85,0xE5,0xF3,0xE7,0x24,0x48,0xFB,0x23 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewStatics3>{ static constexpr guid value{ 0xA28D7594,0x8C41,0x4E13,{ 0x97,0x19,0x51,0x64,0x79,0x6F,0xE4,0xC7 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewStatics4>{ static constexpr guid value{ 0x08FD8D33,0x2611,0x5336,{ 0xA3,0x15,0xD9,0x8E,0x63,0x66,0xC9,0xDB } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ static constexpr guid value{ 0x975F2F1E,0xE656,0x4C5E,{ 0xA0,0xA1,0x71,0x7C,0x6F,0xFA,0x7D,0x64 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ static constexpr guid value{ 0x60E995CD,0x4FC2,0x48C4,{ 0xB8,0xE3,0x39,0x5F,0x2B,0x9F,0x0F,0xC1 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ static constexpr guid value{ 0x92059420,0x80A7,0x486D,{ 0xB2,0x1F,0xC7,0xA4,0xA2,0x42,0xA3,0x83 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewTitleBar>{ static constexpr guid value{ 0x00924AC0,0x932B,0x4A6B,{ 0x9C,0x4B,0xDC,0x38,0xC8,0x24,0x78,0xCE } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewTransferContext>{ static constexpr guid value{ 0x8574BC63,0x3C17,0x408E,{ 0x94,0x08,0x8A,0x1A,0x9E,0xA8,0x1B,0xFA } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ static constexpr guid value{ 0x15A89D92,0xDD79,0x4B0B,{ 0xBC,0x47,0xD5,0xF1,0x95,0xF1,0x46,0x61 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IApplicationViewWithContext>{ static constexpr guid value{ 0xBD55D512,0x9DC1,0x44FC,{ 0x85,0x01,0x66,0x66,0x25,0xDF,0x60,0xDC } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPane>{ static constexpr guid value{ 0x640ADA70,0x06F3,0x4C87,{ 0xA6,0x78,0x98,0x29,0xC9,0x12,0x7C,0x28 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPane2>{ static constexpr guid value{ 0x8A6B3F26,0x7090,0x4793,{ 0x94,0x4C,0xC3,0xF2,0xCD,0xE2,0x62,0x76 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPaneControl>{ static constexpr guid value{ 0x088BB24F,0x962F,0x489D,{ 0xAA,0x6E,0xC6,0xBE,0x1A,0x0A,0x6E,0x52 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPaneStatics>{ static constexpr guid value{ 0x95F4AF3A,0xEF47,0x424A,{ 0x97,0x41,0xFD,0x28,0x15,0xEB,0xA2,0xBD } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPaneStatics2>{ static constexpr guid value{ 0x1B63529B,0xD9EC,0x4531,{ 0x84,0x45,0x71,0xBA,0xB9,0xFB,0x82,0x8E } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ static constexpr guid value{ 0xD243E016,0xD907,0x4FCC,{ 0xBB,0x8D,0xF7,0x7B,0xAA,0x50,0x28,0xF1 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IProjectionManagerStatics>{ static constexpr guid value{ 0xB65F913D,0xE2F0,0x4FFD,{ 0xBA,0x95,0x34,0x24,0x16,0x47,0xE4,0x5C } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IProjectionManagerStatics2>{ static constexpr guid value{ 0xF33D2F43,0x2749,0x4CDE,{ 0xB9,0x77,0xC0,0xC4,0x1E,0x74,0x15,0xD1 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IStatusBar>{ static constexpr guid value{ 0x0FFCC5BF,0x98D0,0x4864,{ 0xB1,0xE8,0xB3,0xF4,0x02,0x0B,0xE8,0xB4 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ static constexpr guid value{ 0x76CB2670,0xA3D7,0x49CF,{ 0x82,0x00,0x4F,0x3E,0xED,0xCA,0x27,0xBB } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IStatusBarStatics>{ static constexpr guid value{ 0x8B463FDF,0x422F,0x4561,{ 0x88,0x06,0xFB,0x12,0x89,0xCA,0xDF,0xB7 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettings>{ static constexpr guid value{ 0x85361600,0x1C63,0x4627,{ 0xBC,0xB1,0x3A,0x89,0xE0,0xBC,0x9C,0x55 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettings2>{ static constexpr guid value{ 0xBAD82401,0x2721,0x44F9,{ 0xBB,0x91,0x2B,0xB2,0x28,0xBE,0x44,0x2F } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettings3>{ static constexpr guid value{ 0x03021BE4,0x5254,0x4781,{ 0x81,0x94,0x51,0x68,0xF7,0xD0,0x6D,0x7B } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettings4>{ static constexpr guid value{ 0x52BB3002,0x919B,0x4D6B,{ 0x9B,0x78,0x8D,0xD6,0x6F,0xF4,0xB9,0x3B } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettings5>{ static constexpr guid value{ 0x5349D588,0x0CB5,0x5F05,{ 0xBD,0x34,0x70,0x6B,0x32,0x31,0xF0,0xBD } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ static constexpr guid value{ 0x87AFD4B2,0x9146,0x5F02,{ 0x8F,0x6B,0x06,0xD4,0x54,0x17,0x4C,0x0F } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUIViewSettings>{ static constexpr guid value{ 0xC63657F6,0x8850,0x470D,{ 0x88,0xF8,0x45,0x5E,0x16,0xEA,0x2C,0x26 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IUIViewSettingsStatics>{ static constexpr guid value{ 0x595C97A5,0xF8F6,0x41CF,{ 0xB0,0xFB,0xAA,0xCD,0xB8,0x1F,0xD5,0xF6 } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IViewModePreferences>{ static constexpr guid value{ 0x878FCD3A,0x0B99,0x42C9,{ 0x84,0xD0,0xD3,0xF1,0xD4,0x03,0x55,0x4B } }; };
template <> struct guid_storage<Windows::UI::ViewManagement::IViewModePreferencesStatics>{ static constexpr guid value{ 0x69B60A65,0x5DE5,0x40D8,{ 0x83,0x06,0x38,0x33,0xDF,0x7A,0x22,0x74 } }; };
template <> struct default_interface<Windows::UI::ViewManagement::AccessibilitySettings>{ using type = Windows::UI::ViewManagement::IAccessibilitySettings; };
template <> struct default_interface<Windows::UI::ViewManagement::ActivationViewSwitcher>{ using type = Windows::UI::ViewManagement::IActivationViewSwitcher; };
template <> struct default_interface<Windows::UI::ViewManagement::ApplicationView>{ using type = Windows::UI::ViewManagement::IApplicationView; };
template <> struct default_interface<Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs>{ using type = Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs; };
template <> struct default_interface<Windows::UI::ViewManagement::ApplicationViewScaling>{ using type = Windows::UI::ViewManagement::IApplicationViewScaling; };
template <> struct default_interface<Windows::UI::ViewManagement::ApplicationViewTitleBar>{ using type = Windows::UI::ViewManagement::IApplicationViewTitleBar; };
template <> struct default_interface<Windows::UI::ViewManagement::ApplicationViewTransferContext>{ using type = Windows::UI::ViewManagement::IApplicationViewTransferContext; };
template <> struct default_interface<Windows::UI::ViewManagement::InputPane>{ using type = Windows::UI::ViewManagement::IInputPane; };
template <> struct default_interface<Windows::UI::ViewManagement::InputPaneVisibilityEventArgs>{ using type = Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs; };
template <> struct default_interface<Windows::UI::ViewManagement::StatusBar>{ using type = Windows::UI::ViewManagement::IStatusBar; };
template <> struct default_interface<Windows::UI::ViewManagement::StatusBarProgressIndicator>{ using type = Windows::UI::ViewManagement::IStatusBarProgressIndicator; };
template <> struct default_interface<Windows::UI::ViewManagement::UISettings>{ using type = Windows::UI::ViewManagement::IUISettings; };
template <> struct default_interface<Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs>{ using type = Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs; };
template <> struct default_interface<Windows::UI::ViewManagement::UIViewSettings>{ using type = Windows::UI::ViewManagement::IUIViewSettings; };
template <> struct default_interface<Windows::UI::ViewManagement::ViewModePreferences>{ using type = Windows::UI::ViewManagement::IViewModePreferences; };

template <> struct abi<Windows::UI::ViewManagement::IAccessibilitySettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HighContrast(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HighContrastScheme(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_HighContrastChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_HighContrastChanged(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IActivationViewSwitcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowAsStandaloneAsync(int32_t viewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ShowAsStandaloneWithSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL IsViewPresentedOnActivationVirtualDesktop(int32_t viewId, bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Orientation(Windows::UI::ViewManagement::ApplicationViewOrientation* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdjacentToLeftDisplayEdge(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AdjacentToRightDisplayEdge(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFullScreen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsOnLockScreen(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsScreenCaptureEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsScreenCaptureEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Consolidated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Consolidated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SuppressSystemOverlays(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SuppressSystemOverlays(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VisibleBounds(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_VisibleBoundsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_VisibleBoundsChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL SetDesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode boundsMode, bool* success) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TitleBar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFullScreenMode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryEnterFullScreenMode(bool* success) noexcept = 0;
    virtual int32_t WINRT_CALL ExitFullScreenMode() noexcept = 0;
    virtual int32_t WINRT_CALL ShowStandardSystemOverlays() noexcept = 0;
    virtual int32_t WINRT_CALL TryResizeView(Windows::Foundation::Size value, bool* success) noexcept = 0;
    virtual int32_t WINRT_CALL SetPreferredMinSize(Windows::Foundation::Size minSize) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewMode(Windows::UI::ViewManagement::ApplicationViewMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL IsViewModeSupported(Windows::UI::ViewManagement::ApplicationViewMode viewMode, bool* isViewModeSupported) noexcept = 0;
    virtual int32_t WINRT_CALL TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode viewMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryEnterViewModeWithPreferencesAsync(Windows::UI::ViewManagement::ApplicationViewMode viewMode, void* viewModePreferences, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryConsolidateAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView7>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PersistedStateId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PersistedStateId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationView9>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WindowingEnvironment(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDisplayRegions(void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsUserInitiated(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsAppInitiated(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryUnsnapToFullscreen(bool* success) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetApplicationViewIdForWindow(void* window, int32_t* id) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewScaling>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisableLayoutScaling(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySetDisableLayoutScaling(bool disableLayoutScaling, bool* success) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Value(Windows::UI::ViewManagement::ApplicationViewState* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryUnsnap(bool* success) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** current) noexcept = 0;
    virtual int32_t WINRT_CALL get_TerminateAppOnFinalViewClose(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TerminateAppOnFinalViewClose(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreferredLaunchViewSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PreferredLaunchViewSize(Windows::Foundation::Size value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ClearAllPersistedState() noexcept = 0;
    virtual int32_t WINRT_CALL ClearPersistedState(void* key) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DisableShowingMainViewOnActivation() noexcept = 0;
    virtual int32_t WINRT_CALL TryShowAsStandaloneAsync(int32_t viewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryShowAsStandaloneWithSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryShowAsStandaloneWithAnchorViewAndSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, int32_t anchorViewId, Windows::UI::ViewManagement::ViewSizePreference anchorSizePreference, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SwitchAsync(int32_t viewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SwitchFromViewAsync(int32_t toViewId, int32_t fromViewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SwitchFromViewWithOptionsAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions options, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions options, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DisableSystemViewActivationPolicy() noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode viewMode, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryShowAsViewModeWithPreferencesAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode viewMode, void* viewModePreferences, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewTitleBar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_ForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonBackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonBackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonHoverForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonHoverForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonHoverBackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonHoverBackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonPressedForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonPressedForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonPressedBackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonPressedBackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InactiveForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InactiveForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InactiveBackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InactiveBackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonInactiveForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonInactiveForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ButtonInactiveBackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ButtonInactiveBackgroundColor(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewTransferContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewId(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ViewId(int32_t value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DataPackageFormatId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IApplicationViewWithContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UIContext(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPane>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_Showing(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Showing(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Hiding(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Hiding(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPane2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryShow(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TryHide(bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPaneControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Visible(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Visible(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPaneStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** inputPane) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPaneStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForUIContext(void* context, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EnsuredFocusedElementInView(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EnsuredFocusedElementInView(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IProjectionManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProjectionDisplayAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ProjectionDisplayAvailableChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ProjectionDisplayAvailableChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IProjectionManagerStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StartProjectingWithDeviceInfoAsync(int32_t projectionViewId, int32_t anchorViewId, void* displayDeviceInfo, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect selection, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestStartProjectingWithPlacementAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement prefferedPlacement, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IStatusBar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL HideAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundOpacity(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundOpacity(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForegroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ForegroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProgressIndicator(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Showing(void* eventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Showing(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Hiding(void* eventHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Hiding(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ShowAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL HideAsync(void** returnValue) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Text(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProgressValue(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProgressValue(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IStatusBarStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HandPreference(Windows::UI::ViewManagement::HandPreference* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CursorSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScrollBarSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScrollBarArrowSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScrollBarThumbBoxSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MessageDuration(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AnimationsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CaretBrowsingEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CaretBlinkRate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CaretWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DoubleClickTime(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MouseHoverTime(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL UIElementColor(Windows::UI::ViewManagement::UIElementType desiredElement, struct struct_Windows_UI_Color* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettings2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextScaleFactor(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_TextScaleFactorChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_TextScaleFactorChanged(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettings3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetColorValue(Windows::UI::ViewManagement::UIColorType desiredColor, struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ColorValuesChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ColorValuesChanged(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettings4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AdvancedEffectsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AdvancedEffectsEnabledChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AdvancedEffectsEnabledChanged(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettings5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AutoHideScrollBars(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AutoHideScrollBarsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AutoHideScrollBarsChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::ViewManagement::IUIViewSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserInteractionMode(Windows::UI::ViewManagement::UserInteractionMode* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IUIViewSettingsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentView(void** current) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IViewModePreferences>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomSize(Windows::Foundation::Size* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CustomSize(Windows::Foundation::Size value) noexcept = 0;
};};

template <> struct abi<Windows::UI::ViewManagement::IViewModePreferencesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateDefault(Windows::UI::ViewManagement::ApplicationViewMode mode, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_ViewManagement_IAccessibilitySettings
{
    bool HighContrast() const;
    hstring HighContrastScheme() const;
    winrt::event_token HighContrastChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const& handler) const;
    using HighContrastChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IAccessibilitySettings, &impl::abi_t<Windows::UI::ViewManagement::IAccessibilitySettings>::remove_HighContrastChanged>;
    HighContrastChanged_revoker HighContrastChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const& handler) const;
    void HighContrastChanged(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IAccessibilitySettings> { template <typename D> using type = consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IActivationViewSwitcher
{
    Windows::Foundation::IAsyncAction ShowAsStandaloneAsync(int32_t viewId) const;
    Windows::Foundation::IAsyncAction ShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const;
    bool IsViewPresentedOnActivationVirtualDesktop(int32_t viewId) const;
};
template <> struct consume<Windows::UI::ViewManagement::IActivationViewSwitcher> { template <typename D> using type = consume_Windows_UI_ViewManagement_IActivationViewSwitcher<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView
{
    Windows::UI::ViewManagement::ApplicationViewOrientation Orientation() const;
    bool AdjacentToLeftDisplayEdge() const;
    bool AdjacentToRightDisplayEdge() const;
    bool IsFullScreen() const;
    bool IsOnLockScreen() const;
    bool IsScreenCaptureEnabled() const;
    void IsScreenCaptureEnabled(bool value) const;
    void Title(param::hstring const& value) const;
    hstring Title() const;
    int32_t Id() const;
    winrt::event_token Consolidated(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const;
    using Consolidated_revoker = impl::event_revoker<Windows::UI::ViewManagement::IApplicationView, &impl::abi_t<Windows::UI::ViewManagement::IApplicationView>::remove_Consolidated>;
    Consolidated_revoker Consolidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const;
    void Consolidated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView2
{
    bool SuppressSystemOverlays() const;
    void SuppressSystemOverlays(bool value) const;
    Windows::Foundation::Rect VisibleBounds() const;
    winrt::event_token VisibleBoundsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const& handler) const;
    using VisibleBoundsChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IApplicationView2, &impl::abi_t<Windows::UI::ViewManagement::IApplicationView2>::remove_VisibleBoundsChanged>;
    VisibleBoundsChanged_revoker VisibleBoundsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const& handler) const;
    void VisibleBoundsChanged(winrt::event_token const& token) const noexcept;
    bool SetDesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode const& boundsMode) const;
    Windows::UI::ViewManagement::ApplicationViewBoundsMode DesiredBoundsMode() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView3
{
    Windows::UI::ViewManagement::ApplicationViewTitleBar TitleBar() const;
    Windows::UI::ViewManagement::FullScreenSystemOverlayMode FullScreenSystemOverlayMode() const;
    void FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode const& value) const;
    bool IsFullScreenMode() const;
    bool TryEnterFullScreenMode() const;
    void ExitFullScreenMode() const;
    void ShowStandardSystemOverlays() const;
    bool TryResizeView(Windows::Foundation::Size const& value) const;
    void SetPreferredMinSize(Windows::Foundation::Size const& minSize) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView3> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView3<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView4
{
    Windows::UI::ViewManagement::ApplicationViewMode ViewMode() const;
    bool IsViewModeSupported(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
    Windows::Foundation::IAsyncOperation<bool> TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
    Windows::Foundation::IAsyncOperation<bool> TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const;
    Windows::Foundation::IAsyncOperation<bool> TryConsolidateAsync() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView4> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView4<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView7
{
    hstring PersistedStateId() const;
    void PersistedStateId(param::hstring const& value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView7> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView7<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationView9
{
    Windows::UI::WindowManagement::WindowingEnvironment WindowingEnvironment() const;
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> GetDisplayRegions() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationView9> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView9<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs
{
    bool IsUserInitiated() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs2
{
    bool IsAppInitiated() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewFullscreenStatics
{
    bool TryUnsnapToFullscreen() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewFullscreenStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewFullscreenStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewInteropStatics
{
    int32_t GetApplicationViewIdForWindow(Windows::UI::Core::ICoreWindow const& window) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewInteropStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewInteropStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewScaling
{
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewScaling> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewScaling<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics
{
    bool DisableLayoutScaling() const;
    bool TrySetDisableLayoutScaling(bool disableLayoutScaling) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewScalingStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewStatics
{
    Windows::UI::ViewManagement::ApplicationViewState Value() const;
    bool TryUnsnap() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewStatics2
{
    Windows::UI::ViewManagement::ApplicationView GetForCurrentView() const;
    bool TerminateAppOnFinalViewClose() const;
    void TerminateAppOnFinalViewClose(bool value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewStatics2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewStatics3
{
    Windows::UI::ViewManagement::ApplicationViewWindowingMode PreferredLaunchWindowingMode() const;
    void PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode const& value) const;
    Windows::Foundation::Size PreferredLaunchViewSize() const;
    void PreferredLaunchViewSize(Windows::Foundation::Size const& value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewStatics3> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewStatics4
{
    void ClearAllPersistedState() const;
    void ClearPersistedState(param::hstring const& key) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewStatics4> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics4<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics
{
    void DisableShowingMainViewOnActivation() const;
    Windows::Foundation::IAsyncOperation<bool> TryShowAsStandaloneAsync(int32_t viewId) const;
    Windows::Foundation::IAsyncOperation<bool> TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const;
    Windows::Foundation::IAsyncOperation<bool> TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference, int32_t anchorViewId, Windows::UI::ViewManagement::ViewSizePreference const& anchorSizePreference) const;
    Windows::Foundation::IAsyncAction SwitchAsync(int32_t viewId) const;
    Windows::Foundation::IAsyncAction SwitchAsync(int32_t toViewId, int32_t fromViewId) const;
    Windows::Foundation::IAsyncAction SwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const;
    Windows::Foundation::IAsyncOperation<bool> PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics2
{
    void DisableSystemViewActivationPolicy() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3
{
    Windows::Foundation::IAsyncOperation<bool> TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
    Windows::Foundation::IAsyncOperation<bool> TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewTitleBar
{
    void ForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ForegroundColor() const;
    void BackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> BackgroundColor() const;
    void ButtonForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonForegroundColor() const;
    void ButtonBackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonBackgroundColor() const;
    void ButtonHoverForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonHoverForegroundColor() const;
    void ButtonHoverBackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonHoverBackgroundColor() const;
    void ButtonPressedForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonPressedForegroundColor() const;
    void ButtonPressedBackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonPressedBackgroundColor() const;
    void InactiveForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> InactiveForegroundColor() const;
    void InactiveBackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> InactiveBackgroundColor() const;
    void ButtonInactiveForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonInactiveForegroundColor() const;
    void ButtonInactiveBackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ButtonInactiveBackgroundColor() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewTitleBar> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewTransferContext
{
    int32_t ViewId() const;
    void ViewId(int32_t value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewTransferContext> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTransferContext<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewTransferContextStatics
{
    hstring DataPackageFormatId() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewTransferContextStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTransferContextStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IApplicationViewWithContext
{
    Windows::UI::UIContext UIContext() const;
};
template <> struct consume<Windows::UI::ViewManagement::IApplicationViewWithContext> { template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewWithContext<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPane
{
    winrt::event_token Showing(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
    using Showing_revoker = impl::event_revoker<Windows::UI::ViewManagement::IInputPane, &impl::abi_t<Windows::UI::ViewManagement::IInputPane>::remove_Showing>;
    Showing_revoker Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
    void Showing(winrt::event_token const& token) const noexcept;
    winrt::event_token Hiding(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
    using Hiding_revoker = impl::event_revoker<Windows::UI::ViewManagement::IInputPane, &impl::abi_t<Windows::UI::ViewManagement::IInputPane>::remove_Hiding>;
    Hiding_revoker Hiding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
    void Hiding(winrt::event_token const& token) const noexcept;
    Windows::Foundation::Rect OccludedRect() const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPane> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPane<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPane2
{
    bool TryShow() const;
    bool TryHide() const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPane2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPane2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPaneControl
{
    bool Visible() const;
    void Visible(bool value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPaneControl> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneControl<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPaneStatics
{
    Windows::UI::ViewManagement::InputPane GetForCurrentView() const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPaneStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPaneStatics2
{
    Windows::UI::ViewManagement::InputPane GetForUIContext(Windows::UI::UIContext const& context) const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPaneStatics2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneStatics2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs
{
    Windows::Foundation::Rect OccludedRect() const;
    void EnsuredFocusedElementInView(bool value) const;
    bool EnsuredFocusedElementInView() const;
};
template <> struct consume<Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs> { template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IProjectionManagerStatics
{
    Windows::Foundation::IAsyncAction StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const;
    Windows::Foundation::IAsyncAction SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId) const;
    Windows::Foundation::IAsyncAction StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const;
    bool ProjectionDisplayAvailable() const;
    winrt::event_token ProjectionDisplayAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using ProjectionDisplayAvailableChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IProjectionManagerStatics, &impl::abi_t<Windows::UI::ViewManagement::IProjectionManagerStatics>::remove_ProjectionDisplayAvailableChanged>;
    ProjectionDisplayAvailableChanged_revoker ProjectionDisplayAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void ProjectionDisplayAvailableChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IProjectionManagerStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IProjectionManagerStatics2
{
    Windows::Foundation::IAsyncAction StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Devices::Enumeration::DeviceInformation const& displayDeviceInfo) const;
    Windows::Foundation::IAsyncOperation<bool> RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection) const;
    Windows::Foundation::IAsyncOperation<bool> RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& prefferedPlacement) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::UI::ViewManagement::IProjectionManagerStatics2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IStatusBar
{
    Windows::Foundation::IAsyncAction ShowAsync() const;
    Windows::Foundation::IAsyncAction HideAsync() const;
    double BackgroundOpacity() const;
    void BackgroundOpacity(double value) const;
    Windows::Foundation::IReference<Windows::UI::Color> ForegroundColor() const;
    void ForegroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::Foundation::IReference<Windows::UI::Color> BackgroundColor() const;
    void BackgroundColor(optional<Windows::UI::Color> const& value) const;
    Windows::UI::ViewManagement::StatusBarProgressIndicator ProgressIndicator() const;
    Windows::Foundation::Rect OccludedRect() const;
    winrt::event_token Showing(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const;
    using Showing_revoker = impl::event_revoker<Windows::UI::ViewManagement::IStatusBar, &impl::abi_t<Windows::UI::ViewManagement::IStatusBar>::remove_Showing>;
    Showing_revoker Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const;
    void Showing(winrt::event_token const& token) const noexcept;
    winrt::event_token Hiding(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const;
    using Hiding_revoker = impl::event_revoker<Windows::UI::ViewManagement::IStatusBar, &impl::abi_t<Windows::UI::ViewManagement::IStatusBar>::remove_Hiding>;
    Hiding_revoker Hiding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const;
    void Hiding(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IStatusBar> { template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBar<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator
{
    Windows::Foundation::IAsyncAction ShowAsync() const;
    Windows::Foundation::IAsyncAction HideAsync() const;
    hstring Text() const;
    void Text(param::hstring const& value) const;
    Windows::Foundation::IReference<double> ProgressValue() const;
    void ProgressValue(optional<double> const& value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IStatusBarProgressIndicator> { template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IStatusBarStatics
{
    Windows::UI::ViewManagement::StatusBar GetForCurrentView() const;
};
template <> struct consume<Windows::UI::ViewManagement::IStatusBarStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBarStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettings
{
    Windows::UI::ViewManagement::HandPreference HandPreference() const;
    Windows::Foundation::Size CursorSize() const;
    Windows::Foundation::Size ScrollBarSize() const;
    Windows::Foundation::Size ScrollBarArrowSize() const;
    Windows::Foundation::Size ScrollBarThumbBoxSize() const;
    uint32_t MessageDuration() const;
    bool AnimationsEnabled() const;
    bool CaretBrowsingEnabled() const;
    uint32_t CaretBlinkRate() const;
    uint32_t CaretWidth() const;
    uint32_t DoubleClickTime() const;
    uint32_t MouseHoverTime() const;
    Windows::UI::Color UIElementColor(Windows::UI::ViewManagement::UIElementType const& desiredElement) const;
};
template <> struct consume<Windows::UI::ViewManagement::IUISettings> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettings2
{
    double TextScaleFactor() const;
    winrt::event_token TextScaleFactorChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    using TextScaleFactorChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IUISettings2, &impl::abi_t<Windows::UI::ViewManagement::IUISettings2>::remove_TextScaleFactorChanged>;
    TextScaleFactorChanged_revoker TextScaleFactorChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    void TextScaleFactorChanged(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IUISettings2> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings2<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettings3
{
    Windows::UI::Color GetColorValue(Windows::UI::ViewManagement::UIColorType const& desiredColor) const;
    winrt::event_token ColorValuesChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    using ColorValuesChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IUISettings3, &impl::abi_t<Windows::UI::ViewManagement::IUISettings3>::remove_ColorValuesChanged>;
    ColorValuesChanged_revoker ColorValuesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    void ColorValuesChanged(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IUISettings3> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings3<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettings4
{
    bool AdvancedEffectsEnabled() const;
    winrt::event_token AdvancedEffectsEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    using AdvancedEffectsEnabledChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IUISettings4, &impl::abi_t<Windows::UI::ViewManagement::IUISettings4>::remove_AdvancedEffectsEnabledChanged>;
    AdvancedEffectsEnabledChanged_revoker AdvancedEffectsEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const;
    void AdvancedEffectsEnabledChanged(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IUISettings4> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings4<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettings5
{
    bool AutoHideScrollBars() const;
    winrt::event_token AutoHideScrollBarsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const;
    using AutoHideScrollBarsChanged_revoker = impl::event_revoker<Windows::UI::ViewManagement::IUISettings5, &impl::abi_t<Windows::UI::ViewManagement::IUISettings5>::remove_AutoHideScrollBarsChanged>;
    AutoHideScrollBarsChanged_revoker AutoHideScrollBarsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const;
    void AutoHideScrollBarsChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::ViewManagement::IUISettings5> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings5<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUISettingsAutoHideScrollBarsChangedEventArgs
{
};
template <> struct consume<Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettingsAutoHideScrollBarsChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUIViewSettings
{
    Windows::UI::ViewManagement::UserInteractionMode UserInteractionMode() const;
};
template <> struct consume<Windows::UI::ViewManagement::IUIViewSettings> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUIViewSettings<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IUIViewSettingsStatics
{
    Windows::UI::ViewManagement::UIViewSettings GetForCurrentView() const;
};
template <> struct consume<Windows::UI::ViewManagement::IUIViewSettingsStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IUIViewSettingsStatics<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IViewModePreferences
{
    Windows::UI::ViewManagement::ViewSizePreference ViewSizePreference() const;
    void ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference const& value) const;
    Windows::Foundation::Size CustomSize() const;
    void CustomSize(Windows::Foundation::Size const& value) const;
};
template <> struct consume<Windows::UI::ViewManagement::IViewModePreferences> { template <typename D> using type = consume_Windows_UI_ViewManagement_IViewModePreferences<D>; };

template <typename D>
struct consume_Windows_UI_ViewManagement_IViewModePreferencesStatics
{
    Windows::UI::ViewManagement::ViewModePreferences CreateDefault(Windows::UI::ViewManagement::ApplicationViewMode const& mode) const;
};
template <> struct consume<Windows::UI::ViewManagement::IViewModePreferencesStatics> { template <typename D> using type = consume_Windows_UI_ViewManagement_IViewModePreferencesStatics<D>; };

}
