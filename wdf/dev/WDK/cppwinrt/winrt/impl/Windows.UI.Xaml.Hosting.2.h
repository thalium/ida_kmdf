// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.WindowManagement.1.h"
#include "winrt/impl/Windows.UI.Xaml.1.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.1.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Xaml.Hosting.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting {

struct WINRT_EBO DesignerAppExitedEventArgs :
    Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs
{
    DesignerAppExitedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DesignerAppManager :
    Windows::UI::Xaml::Hosting::IDesignerAppManager,
    impl::require<DesignerAppManager, Windows::Foundation::IClosable>
{
    DesignerAppManager(std::nullptr_t) noexcept {}
    DesignerAppManager(param::hstring const& appUserModelId);
};

struct WINRT_EBO DesignerAppView :
    Windows::UI::Xaml::Hosting::IDesignerAppView,
    impl::require<DesignerAppView, Windows::Foundation::IClosable>
{
    DesignerAppView(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DesktopWindowXamlSource :
    Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource,
    impl::require<DesktopWindowXamlSource, Windows::Foundation::IClosable>
{
    DesktopWindowXamlSource(std::nullptr_t) noexcept {}
    DesktopWindowXamlSource();
};

struct WINRT_EBO DesktopWindowXamlSourceGotFocusEventArgs :
    Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs
{
    DesktopWindowXamlSourceGotFocusEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DesktopWindowXamlSourceTakeFocusRequestedEventArgs :
    Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs
{
    DesktopWindowXamlSourceTakeFocusRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ElementCompositionPreview :
    Windows::UI::Xaml::Hosting::IElementCompositionPreview
{
    ElementCompositionPreview(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Visual GetElementVisual(Windows::UI::Xaml::UIElement const& element);
    static Windows::UI::Composition::Visual GetElementChildVisual(Windows::UI::Xaml::UIElement const& element);
    static void SetElementChildVisual(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::Visual const& visual);
    static Windows::UI::Composition::CompositionPropertySet GetScrollViewerManipulationPropertySet(Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer);
    static void SetImplicitShowAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation);
    static void SetImplicitHideAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation);
    static void SetIsTranslationEnabled(Windows::UI::Xaml::UIElement const& element, bool value);
    static Windows::UI::Composition::CompositionPropertySet GetPointerPositionPropertySet(Windows::UI::Xaml::UIElement const& targetElement);
    static void SetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow, Windows::UI::Xaml::UIElement const& xamlContent);
    static Windows::UI::Xaml::UIElement GetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow);
};

struct WINRT_EBO WindowsXamlManager :
    Windows::UI::Xaml::Hosting::IWindowsXamlManager,
    impl::require<WindowsXamlManager, Windows::Foundation::IClosable>
{
    WindowsXamlManager(std::nullptr_t) noexcept {}
    static Windows::UI::Xaml::Hosting::WindowsXamlManager InitializeForCurrentThread();
};

struct WINRT_EBO XamlSourceFocusNavigationRequest :
    Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest
{
    XamlSourceFocusNavigationRequest(std::nullptr_t) noexcept {}
    XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason);
    XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect);
    XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId);
};

struct WINRT_EBO XamlSourceFocusNavigationResult :
    Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult
{
    XamlSourceFocusNavigationResult(std::nullptr_t) noexcept {}
    XamlSourceFocusNavigationResult(bool focusMoved);
};

struct WINRT_EBO XamlUIPresenter :
    Windows::UI::Xaml::Hosting::IXamlUIPresenter
{
    XamlUIPresenter(std::nullptr_t) noexcept {}
    static bool CompleteTimelinesAutomatically();
    static void CompleteTimelinesAutomatically(bool value);
    static void SetHost(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host);
    static void NotifyWindowSizeChanged();
    static Windows::Foundation::Rect GetFlyoutPlacementTargetInfo(Windows::UI::Xaml::FrameworkElement const& placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks);
    static Windows::Foundation::Rect GetFlyoutPlacement(Windows::Foundation::Rect const& placementTargetBounds, Windows::Foundation::Size const& controlSize, Windows::Foundation::Size const& minControlSize, Windows::Foundation::Rect const& containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement);
};

}
