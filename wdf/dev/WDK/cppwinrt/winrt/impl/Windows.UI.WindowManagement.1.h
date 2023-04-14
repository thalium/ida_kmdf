// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.UI.WindowManagement.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

struct WINRT_EBO IAppWindow :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindow>
{
    IAppWindow(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowChangedEventArgs>
{
    IAppWindowChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowCloseRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowCloseRequestedEventArgs>
{
    IAppWindowCloseRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowClosedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowClosedEventArgs>
{
    IAppWindowClosedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowFrame>
{
    IAppWindowFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowFrameStyle :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowFrameStyle>
{
    IAppWindowFrameStyle(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowPlacement :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowPlacement>
{
    IAppWindowPlacement(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowPresentationConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowPresentationConfiguration>
{
    IAppWindowPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowPresentationConfigurationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowPresentationConfigurationFactory>
{
    IAppWindowPresentationConfigurationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowPresenter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowPresenter>
{
    IAppWindowPresenter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowStatics>
{
    IAppWindowStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowTitleBar :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowTitleBar>
{
    IAppWindowTitleBar(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowTitleBarOcclusion :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowTitleBarOcclusion>
{
    IAppWindowTitleBarOcclusion(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IAppWindowTitleBarVisibility :
    Windows::Foundation::IInspectable,
    impl::consume_t<IAppWindowTitleBarVisibility>
{
    IAppWindowTitleBarVisibility(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompactOverlayPresentationConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompactOverlayPresentationConfiguration>
{
    ICompactOverlayPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDefaultPresentationConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDefaultPresentationConfiguration>
{
    IDefaultPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayRegion :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayRegion>
{
    IDisplayRegion(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFullScreenPresentationConfiguration :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFullScreenPresentationConfiguration>
{
    IFullScreenPresentationConfiguration(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowingEnvironment :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowingEnvironment>
{
    IWindowingEnvironment(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowingEnvironmentAddedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowingEnvironmentAddedEventArgs>
{
    IWindowingEnvironmentAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowingEnvironmentChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowingEnvironmentChangedEventArgs>
{
    IWindowingEnvironmentChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowingEnvironmentRemovedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowingEnvironmentRemovedEventArgs>
{
    IWindowingEnvironmentRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowingEnvironmentStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowingEnvironmentStatics>
{
    IWindowingEnvironmentStatics(std::nullptr_t = nullptr) noexcept {}
};

}
