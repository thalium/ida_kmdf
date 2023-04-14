// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.UI.WindowManagement.0.h"
#include "winrt/impl/Windows.UI.Xaml.0.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.0.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.UI.Xaml.Hosting.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting {

struct WINRT_EBO IDesignerAppExitedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesignerAppExitedEventArgs>
{
    IDesignerAppExitedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesignerAppManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesignerAppManager>
{
    IDesignerAppManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesignerAppManagerFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesignerAppManagerFactory>
{
    IDesignerAppManagerFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesignerAppView :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesignerAppView>
{
    IDesignerAppView(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesktopWindowXamlSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesktopWindowXamlSource>
{
    IDesktopWindowXamlSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesktopWindowXamlSourceFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesktopWindowXamlSourceFactory>
{
    IDesktopWindowXamlSourceFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesktopWindowXamlSourceGotFocusEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesktopWindowXamlSourceGotFocusEventArgs>
{
    IDesktopWindowXamlSourceGotFocusEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDesktopWindowXamlSourceTakeFocusRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>
{
    IDesktopWindowXamlSourceTakeFocusRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IElementCompositionPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IElementCompositionPreview>
{
    IElementCompositionPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IElementCompositionPreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IElementCompositionPreviewStatics>
{
    IElementCompositionPreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IElementCompositionPreviewStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IElementCompositionPreviewStatics2>
{
    IElementCompositionPreviewStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IElementCompositionPreviewStatics3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IElementCompositionPreviewStatics3>
{
    IElementCompositionPreviewStatics3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowsXamlManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowsXamlManager>
{
    IWindowsXamlManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWindowsXamlManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWindowsXamlManagerStatics>
{
    IWindowsXamlManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlSourceFocusNavigationRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlSourceFocusNavigationRequest>
{
    IXamlSourceFocusNavigationRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlSourceFocusNavigationRequestFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlSourceFocusNavigationRequestFactory>
{
    IXamlSourceFocusNavigationRequestFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlSourceFocusNavigationResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlSourceFocusNavigationResult>
{
    IXamlSourceFocusNavigationResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlSourceFocusNavigationResultFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlSourceFocusNavigationResultFactory>
{
    IXamlSourceFocusNavigationResultFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenter>
{
    IXamlUIPresenter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenterHost :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenterHost>
{
    IXamlUIPresenterHost(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenterHost2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenterHost2>
{
    IXamlUIPresenterHost2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenterHost3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenterHost3>
{
    IXamlUIPresenterHost3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenterStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenterStatics>
{
    IXamlUIPresenterStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IXamlUIPresenterStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IXamlUIPresenterStatics2>
{
    IXamlUIPresenterStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
