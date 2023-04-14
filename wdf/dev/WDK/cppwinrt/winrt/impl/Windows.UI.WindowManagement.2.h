// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.WindowManagement.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct WINRT_EBO AppWindow :
    Windows::UI::WindowManagement::IAppWindow
{
    AppWindow(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow> TryCreateAsync();
    static void ClearAllPersistedState();
    static void ClearPersistedState(param::hstring const& key);
};

struct WINRT_EBO AppWindowChangedEventArgs :
    Windows::UI::WindowManagement::IAppWindowChangedEventArgs
{
    AppWindowChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowCloseRequestedEventArgs :
    Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs
{
    AppWindowCloseRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowClosedEventArgs :
    Windows::UI::WindowManagement::IAppWindowClosedEventArgs
{
    AppWindowClosedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowFrame :
    Windows::UI::WindowManagement::IAppWindowFrame,
    impl::require<AppWindowFrame, Windows::UI::WindowManagement::IAppWindowFrameStyle>
{
    AppWindowFrame(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowPlacement :
    Windows::UI::WindowManagement::IAppWindowPlacement
{
    AppWindowPlacement(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowPresentationConfiguration :
    Windows::UI::WindowManagement::IAppWindowPresentationConfiguration
{
    AppWindowPresentationConfiguration(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowPresenter :
    Windows::UI::WindowManagement::IAppWindowPresenter
{
    AppWindowPresenter(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowTitleBar :
    Windows::UI::WindowManagement::IAppWindowTitleBar,
    impl::require<AppWindowTitleBar, Windows::UI::WindowManagement::IAppWindowTitleBarVisibility>
{
    AppWindowTitleBar(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AppWindowTitleBarOcclusion :
    Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion
{
    AppWindowTitleBarOcclusion(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompactOverlayPresentationConfiguration :
    Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration,
    impl::base<CompactOverlayPresentationConfiguration, Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
    impl::require<CompactOverlayPresentationConfiguration, Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
{
    CompactOverlayPresentationConfiguration(std::nullptr_t) noexcept {}
    CompactOverlayPresentationConfiguration();
};

struct WINRT_EBO DefaultPresentationConfiguration :
    Windows::UI::WindowManagement::IDefaultPresentationConfiguration,
    impl::base<DefaultPresentationConfiguration, Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
    impl::require<DefaultPresentationConfiguration, Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
{
    DefaultPresentationConfiguration(std::nullptr_t) noexcept {}
    DefaultPresentationConfiguration();
};

struct WINRT_EBO DisplayRegion :
    Windows::UI::WindowManagement::IDisplayRegion
{
    DisplayRegion(std::nullptr_t) noexcept {}
};

struct WINRT_EBO FullScreenPresentationConfiguration :
    Windows::UI::WindowManagement::IFullScreenPresentationConfiguration,
    impl::base<FullScreenPresentationConfiguration, Windows::UI::WindowManagement::AppWindowPresentationConfiguration>,
    impl::require<FullScreenPresentationConfiguration, Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
{
    FullScreenPresentationConfiguration(std::nullptr_t) noexcept {}
    FullScreenPresentationConfiguration();
};

struct WINRT_EBO WindowingEnvironment :
    Windows::UI::WindowManagement::IWindowingEnvironment
{
    WindowingEnvironment(std::nullptr_t) noexcept {}
    static Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> FindAll();
    static Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> FindAll(Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind);
};

struct WINRT_EBO WindowingEnvironmentAddedEventArgs :
    Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs
{
    WindowingEnvironmentAddedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WindowingEnvironmentChangedEventArgs :
    Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs
{
    WindowingEnvironmentChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WindowingEnvironmentRemovedEventArgs :
    Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs
{
    WindowingEnvironmentRemovedEventArgs(std::nullptr_t) noexcept {}
};

}
