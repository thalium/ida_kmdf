// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.Web.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.Web.UI.0.h"

WINRT_EXPORT namespace winrt::Windows::Web::UI {

struct WINRT_EBO IWebViewControl :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControl>
{
    IWebViewControl(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControl2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControl2>
{
    IWebViewControl2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlContentLoadingEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlContentLoadingEventArgs>
{
    IWebViewControlContentLoadingEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlDOMContentLoadedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlDOMContentLoadedEventArgs>
{
    IWebViewControlDOMContentLoadedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlDeferredPermissionRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlDeferredPermissionRequest>
{
    IWebViewControlDeferredPermissionRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlLongRunningScriptDetectedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlLongRunningScriptDetectedEventArgs>
{
    IWebViewControlLongRunningScriptDetectedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlNavigationCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlNavigationCompletedEventArgs>
{
    IWebViewControlNavigationCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlNavigationStartingEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlNavigationStartingEventArgs>
{
    IWebViewControlNavigationStartingEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlNewWindowRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlNewWindowRequestedEventArgs>
{
    IWebViewControlNewWindowRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlNewWindowRequestedEventArgs2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlNewWindowRequestedEventArgs2>
{
    IWebViewControlNewWindowRequestedEventArgs2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlPermissionRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlPermissionRequest>
{
    IWebViewControlPermissionRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlPermissionRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlPermissionRequestedEventArgs>
{
    IWebViewControlPermissionRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlScriptNotifyEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlScriptNotifyEventArgs>
{
    IWebViewControlScriptNotifyEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlSettings>
{
    IWebViewControlSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs>
{
    IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlUnviewableContentIdentifiedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlUnviewableContentIdentifiedEventArgs>
{
    IWebViewControlUnviewableContentIdentifiedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlWebResourceRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlWebResourceRequestedEventArgs>
{
    IWebViewControlWebResourceRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
