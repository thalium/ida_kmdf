// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.UI.2.h"
#include "winrt/Windows.Web.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControl<D>::Source() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::Source(Windows::Foundation::Uri const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->put_Source(get_abi(source)));
}

template <typename D> hstring consume_Windows_Web_UI_IWebViewControl<D>::DocumentTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_DocumentTitle(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControl<D>::CanGoBack() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_CanGoBack(&value));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControl<D>::CanGoForward() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_CanGoForward(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::DefaultBackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->put_DefaultBackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_Web_UI_IWebViewControl<D>::DefaultBackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_DefaultBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElement() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_ContainsFullScreenElement(&value));
    return value;
}

template <typename D> Windows::Web::UI::WebViewControlSettings consume_Windows_Web_UI_IWebViewControl<D>::Settings() const
{
    Windows::Web::UI::WebViewControlSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_Settings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::UI::WebViewControlDeferredPermissionRequest> consume_Windows_Web_UI_IWebViewControl<D>::DeferredPermissionRequests() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::UI::WebViewControlDeferredPermissionRequest> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->get_DeferredPermissionRequests(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::GoForward() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->GoForward());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::GoBack() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->GoBack());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::Refresh() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->Refresh());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->Stop());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::Navigate(Windows::Foundation::Uri const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->Navigate(get_abi(source)));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NavigateToString(param::hstring const& text) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->NavigateToString(get_abi(text)));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NavigateToLocalStreamUri(Windows::Foundation::Uri const& source, Windows::Web::IUriToStreamResolver const& streamResolver) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->NavigateToLocalStreamUri(get_abi(source), get_abi(streamResolver)));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NavigateWithHttpRequestMessage(Windows::Web::Http::HttpRequestMessage const& requestMessage) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->NavigateWithHttpRequestMessage(get_abi(requestMessage)));
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Web_UI_IWebViewControl<D>::InvokeScriptAsync(param::hstring const& scriptName, param::async_iterable<hstring> const& arguments) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->InvokeScriptAsync(get_abi(scriptName), get_abi(arguments), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Web_UI_IWebViewControl<D>::CapturePreviewToStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->CapturePreviewToStreamAsync(get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackage> consume_Windows_Web_UI_IWebViewControl<D>::CaptureSelectedContentToDataPackageAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackage> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->CaptureSelectedContentToDataPackageAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControl<D>::BuildLocalStreamUri(param::hstring const& contentIdentifier, param::hstring const& relativePath) const
{
    Windows::Foundation::Uri result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->BuildLocalStreamUri(get_abi(contentIdentifier), get_abi(relativePath), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::GetDeferredPermissionRequestById(uint32_t id, Windows::Web::UI::WebViewControlDeferredPermissionRequest& result) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->GetDeferredPermissionRequestById(id, put_abi(result)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_NavigationStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting_revoker consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationStarting_revoker>(this, NavigationStarting(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NavigationStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_NavigationStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_ContentLoading(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading_revoker consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ContentLoading_revoker>(this, ContentLoading(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::ContentLoading(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_ContentLoading(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_DOMContentLoaded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded_revoker consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DOMContentLoaded_revoker>(this, DOMContentLoaded(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::DOMContentLoaded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_DOMContentLoaded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_NavigationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted_revoker consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NavigationCompleted_revoker>(this, NavigationCompleted(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NavigationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_NavigationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_FrameNavigationStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameNavigationStarting_revoker>(this, FrameNavigationStarting(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_FrameNavigationStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_FrameContentLoading(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameContentLoading_revoker>(this, FrameContentLoading(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::FrameContentLoading(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_FrameContentLoading(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_FrameDOMContentLoaded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameDOMContentLoaded_revoker>(this, FrameDOMContentLoaded(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::FrameDOMContentLoaded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_FrameDOMContentLoaded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_FrameNavigationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted_revoker consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameNavigationCompleted_revoker>(this, FrameNavigationCompleted(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::FrameNavigationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_FrameNavigationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_ScriptNotify(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify_revoker consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ScriptNotify_revoker>(this, ScriptNotify(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::ScriptNotify(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_ScriptNotify(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_LongRunningScriptDetected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected_revoker consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LongRunningScriptDetected_revoker>(this, LongRunningScriptDetected(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::LongRunningScriptDetected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_LongRunningScriptDetected(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_UnsafeContentWarningDisplaying(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UnsafeContentWarningDisplaying_revoker>(this, UnsafeContentWarningDisplaying(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::UnsafeContentWarningDisplaying(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_UnsafeContentWarningDisplaying(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_UnviewableContentIdentified(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UnviewableContentIdentified_revoker>(this, UnviewableContentIdentified(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::UnviewableContentIdentified(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_UnviewableContentIdentified(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_PermissionRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PermissionRequested_revoker>(this, PermissionRequested(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::PermissionRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_PermissionRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_UnsupportedUriSchemeIdentified(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified_revoker consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UnsupportedUriSchemeIdentified_revoker>(this, UnsupportedUriSchemeIdentified(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::UnsupportedUriSchemeIdentified(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_UnsupportedUriSchemeIdentified(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_NewWindowRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NewWindowRequested_revoker>(this, NewWindowRequested(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::NewWindowRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_NewWindowRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_ContainsFullScreenElementChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged_revoker consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ContainsFullScreenElementChanged_revoker>(this, ContainsFullScreenElementChanged(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::ContainsFullScreenElementChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_ContainsFullScreenElementChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl)->add_WebResourceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested_revoker consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, WebResourceRequested_revoker>(this, WebResourceRequested(handler));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl<D>::WebResourceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::IWebViewControl)->remove_WebResourceRequested(get_abi(token)));
}

template <typename D> void consume_Windows_Web_UI_IWebViewControl2<D>::AddInitializeScript(param::hstring const& script) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControl2)->AddInitializeScript(get_abi(script)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlContentLoadingEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlContentLoadingEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlDOMContentLoadedEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_Id(&value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::UI::WebViewControlPermissionType consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::PermissionType() const
{
    Windows::Web::UI::WebViewControlPermissionType value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->get_PermissionType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Allow() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->Allow());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlDeferredPermissionRequest<D>::Deny() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlDeferredPermissionRequest)->Deny());
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::ExecutionTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->get_ExecutionTime(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::StopPageScriptExecution() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->get_StopPageScriptExecution(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlLongRunningScriptDetectedEventArgs<D>::StopPageScriptExecution(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs)->put_StopPageScriptExecution(value));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::IsSuccess() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_IsSuccess(&value));
    return value;
}

template <typename D> Windows::Web::WebErrorStatus consume_Windows_Web_UI_IWebViewControlNavigationCompletedEventArgs<D>::WebErrorStatus() const
{
    Windows::Web::WebErrorStatus value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs)->get_WebErrorStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlNavigationStartingEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNavigationStartingEventArgs)->put_Cancel(value));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Referrer() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Referrer(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Web::UI::IWebViewControl consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::NewWindow() const
{
    Windows::Web::UI::IWebViewControl value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->get_NewWindow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::NewWindow(Windows::Web::UI::IWebViewControl const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->put_NewWindow(get_abi(value)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Web_UI_IWebViewControlNewWindowRequestedEventArgs2<D>::GetDeferral() const
{
    Windows::Foundation::Deferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> uint32_t consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->get_Id(&value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::UI::WebViewControlPermissionType consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::PermissionType() const
{
    Windows::Web::UI::WebViewControlPermissionType value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->get_PermissionType(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::UI::WebViewControlPermissionState consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::State() const
{
    Windows::Web::UI::WebViewControlPermissionState value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Defer() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->Defer());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Allow() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->Allow());
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlPermissionRequest<D>::Deny() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequest)->Deny());
}

template <typename D> Windows::Web::UI::WebViewControlPermissionRequest consume_Windows_Web_UI_IWebViewControlPermissionRequestedEventArgs<D>::PermissionRequest() const
{
    Windows::Web::UI::WebViewControlPermissionRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs)->get_PermissionRequest(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlScriptNotifyEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_UI_IWebViewControlScriptNotifyEventArgs<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlScriptNotifyEventArgs)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlSettings<D>::IsJavaScriptEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->put_IsJavaScriptEnabled(value));
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlSettings<D>::IsJavaScriptEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->get_IsJavaScriptEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlSettings<D>::IsIndexedDBEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->put_IsIndexedDBEnabled(value));
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlSettings<D>::IsIndexedDBEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->get_IsIndexedDBEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlSettings<D>::IsScriptNotifyAllowed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->put_IsScriptNotifyAllowed(value));
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlSettings<D>::IsScriptNotifyAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlSettings)->get_IsScriptNotifyAllowed(&value));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::Referrer() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_Referrer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_UI_IWebViewControlUnviewableContentIdentifiedEventArgs<D>::MediaType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs)->get_MediaType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Request() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Response(Windows::Web::Http::HttpResponseMessage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->put_Response(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_UI_IWebViewControlWebResourceRequestedEventArgs<D>::Response() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs)->get_Response(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControl> : produce_base<D, Windows::Web::UI::IWebViewControl>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Source(*reinterpret_cast<Windows::Foundation::Uri const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DocumentTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanGoBack(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGoBack, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanGoBack());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanGoForward(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGoForward, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanGoForward());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultBackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultBackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().DefaultBackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultBackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DefaultBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContainsFullScreenElement(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsFullScreenElement, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ContainsFullScreenElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Settings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Settings, WINRT_WRAP(Windows::Web::UI::WebViewControlSettings));
            *value = detach_from<Windows::Web::UI::WebViewControlSettings>(this->shim().Settings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeferredPermissionRequests(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferredPermissionRequests, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::UI::WebViewControlDeferredPermissionRequest>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::UI::WebViewControlDeferredPermissionRequest>>(this->shim().DeferredPermissionRequests());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GoForward() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoForward, WINRT_WRAP(void));
            this->shim().GoForward();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GoBack() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoBack, WINRT_WRAP(void));
            this->shim().GoBack();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Refresh() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Refresh, WINRT_WRAP(void));
            this->shim().Refresh();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Navigate(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Navigate, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Navigate(*reinterpret_cast<Windows::Foundation::Uri const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NavigateToString(void* text) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateToString, WINRT_WRAP(void), hstring const&);
            this->shim().NavigateToString(*reinterpret_cast<hstring const*>(&text));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NavigateToLocalStreamUri(void* source, void* streamResolver) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateToLocalStreamUri, WINRT_WRAP(void), Windows::Foundation::Uri const&, Windows::Web::IUriToStreamResolver const&);
            this->shim().NavigateToLocalStreamUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&source), *reinterpret_cast<Windows::Web::IUriToStreamResolver const*>(&streamResolver));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NavigateWithHttpRequestMessage(void* requestMessage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateWithHttpRequestMessage, WINRT_WRAP(void), Windows::Web::Http::HttpRequestMessage const&);
            this->shim().NavigateWithHttpRequestMessage(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&requestMessage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvokeScriptAsync(void* scriptName, void* arguments, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvokeScriptAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().InvokeScriptAsync(*reinterpret_cast<hstring const*>(&scriptName), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&arguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CapturePreviewToStreamAsync(void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturePreviewToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CapturePreviewToStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CaptureSelectedContentToDataPackageAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureSelectedContentToDataPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackage>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackage>>(this->shim().CaptureSelectedContentToDataPackageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BuildLocalStreamUri(void* contentIdentifier, void* relativePath, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildLocalStreamUri, WINRT_WRAP(Windows::Foundation::Uri), hstring const&, hstring const&);
            *result = detach_from<Windows::Foundation::Uri>(this->shim().BuildLocalStreamUri(*reinterpret_cast<hstring const*>(&contentIdentifier), *reinterpret_cast<hstring const*>(&relativePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferredPermissionRequestById(uint32_t id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferredPermissionRequestById, WINRT_WRAP(void), uint32_t, Windows::Web::UI::WebViewControlDeferredPermissionRequest&);
            this->shim().GetDeferredPermissionRequestById(id, *reinterpret_cast<Windows::Web::UI::WebViewControlDeferredPermissionRequest*>(result));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_NavigationStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ContentLoading(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLoading, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContentLoading(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContentLoading(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContentLoading, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContentLoading(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DOMContentLoaded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DOMContentLoaded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DOMContentLoaded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DOMContentLoaded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DOMContentLoaded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DOMContentLoaded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NavigationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NavigationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NavigationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NavigationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FrameNavigationStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameNavigationStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameNavigationStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameNavigationStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameNavigationStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameNavigationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FrameContentLoading(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameContentLoading, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameContentLoading(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlContentLoadingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameContentLoading(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameContentLoading, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameContentLoading(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FrameDOMContentLoaded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameDOMContentLoaded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameDOMContentLoaded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameDOMContentLoaded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameDOMContentLoaded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameDOMContentLoaded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FrameNavigationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameNavigationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameNavigationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameNavigationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameNavigationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameNavigationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ScriptNotify(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScriptNotify, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ScriptNotify(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlScriptNotifyEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ScriptNotify(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ScriptNotify, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ScriptNotify(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LongRunningScriptDetected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LongRunningScriptDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LongRunningScriptDetected(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LongRunningScriptDetected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LongRunningScriptDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LongRunningScriptDetected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UnsafeContentWarningDisplaying(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnsafeContentWarningDisplaying, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UnsafeContentWarningDisplaying(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UnsafeContentWarningDisplaying(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UnsafeContentWarningDisplaying, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UnsafeContentWarningDisplaying(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UnviewableContentIdentified(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnviewableContentIdentified, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UnviewableContentIdentified(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UnviewableContentIdentified(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UnviewableContentIdentified, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UnviewableContentIdentified(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PermissionRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PermissionRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PermissionRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PermissionRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PermissionRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PermissionRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UnsupportedUriSchemeIdentified(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnsupportedUriSchemeIdentified, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UnsupportedUriSchemeIdentified(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UnsupportedUriSchemeIdentified(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UnsupportedUriSchemeIdentified, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UnsupportedUriSchemeIdentified(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NewWindowRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewWindowRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NewWindowRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NewWindowRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NewWindowRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NewWindowRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ContainsFullScreenElementChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsFullScreenElementChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContainsFullScreenElementChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContainsFullScreenElementChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContainsFullScreenElementChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContainsFullScreenElementChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_WebResourceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebResourceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().WebResourceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::IWebViewControl, Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_WebResourceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(WebResourceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().WebResourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControl2> : produce_base<D, Windows::Web::UI::IWebViewControl2>
{
    int32_t WINRT_CALL AddInitializeScript(void* script) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddInitializeScript, WINRT_WRAP(void), hstring const&);
            this->shim().AddInitializeScript(*reinterpret_cast<hstring const*>(&script));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlContentLoadingEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlContentLoadingEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlDeferredPermissionRequest> : produce_base<D, Windows::Web::UI::IWebViewControlDeferredPermissionRequest>
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

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PermissionType(Windows::Web::UI::WebViewControlPermissionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PermissionType, WINRT_WRAP(Windows::Web::UI::WebViewControlPermissionType));
            *value = detach_from<Windows::Web::UI::WebViewControlPermissionType>(this->shim().PermissionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Allow() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Allow, WINRT_WRAP(void));
            this->shim().Allow();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Deny() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deny, WINRT_WRAP(void));
            this->shim().Deny();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs>
{
    int32_t WINRT_CALL get_ExecutionTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecutionTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ExecutionTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StopPageScriptExecution(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPageScriptExecution, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StopPageScriptExecution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StopPageScriptExecution(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPageScriptExecution, WINRT_WRAP(void), bool);
            this->shim().StopPageScriptExecution(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuccess(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuccess, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebErrorStatus(Windows::Web::WebErrorStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebErrorStatus, WINRT_WRAP(Windows::Web::WebErrorStatus));
            *value = detach_from<Windows::Web::WebErrorStatus>(this->shim().WebErrorStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlNavigationStartingEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlNavigationStartingEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
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
struct produce<D, Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Referrer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Referrer, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Referrer());
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
struct produce<D, Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2> : produce_base<D, Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2>
{
    int32_t WINRT_CALL get_NewWindow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewWindow, WINRT_WRAP(Windows::Web::UI::IWebViewControl));
            *value = detach_from<Windows::Web::UI::IWebViewControl>(this->shim().NewWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NewWindow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewWindow, WINRT_WRAP(void), Windows::Web::UI::IWebViewControl const&);
            this->shim().NewWindow(*reinterpret_cast<Windows::Web::UI::IWebViewControl const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *deferral = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlPermissionRequest> : produce_base<D, Windows::Web::UI::IWebViewControlPermissionRequest>
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

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PermissionType(Windows::Web::UI::WebViewControlPermissionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PermissionType, WINRT_WRAP(Windows::Web::UI::WebViewControlPermissionType));
            *value = detach_from<Windows::Web::UI::WebViewControlPermissionType>(this->shim().PermissionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Web::UI::WebViewControlPermissionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Web::UI::WebViewControlPermissionState));
            *value = detach_from<Windows::Web::UI::WebViewControlPermissionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Defer() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Defer, WINRT_WRAP(void));
            this->shim().Defer();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Allow() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Allow, WINRT_WRAP(void));
            this->shim().Allow();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Deny() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deny, WINRT_WRAP(void));
            this->shim().Deny();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs>
{
    int32_t WINRT_CALL get_PermissionRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PermissionRequest, WINRT_WRAP(Windows::Web::UI::WebViewControlPermissionRequest));
            *value = detach_from<Windows::Web::UI::WebViewControlPermissionRequest>(this->shim().PermissionRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlScriptNotifyEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlScriptNotifyEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlSettings> : produce_base<D, Windows::Web::UI::IWebViewControlSettings>
{
    int32_t WINRT_CALL put_IsJavaScriptEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsJavaScriptEnabled, WINRT_WRAP(void), bool);
            this->shim().IsJavaScriptEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsJavaScriptEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsJavaScriptEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsJavaScriptEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsIndexedDBEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIndexedDBEnabled, WINRT_WRAP(void), bool);
            this->shim().IsIndexedDBEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIndexedDBEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIndexedDBEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIndexedDBEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsScriptNotifyAllowed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScriptNotifyAllowed, WINRT_WRAP(void), bool);
            this->shim().IsScriptNotifyAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsScriptNotifyAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScriptNotifyAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScriptNotifyAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
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
struct produce<D, Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Referrer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Referrer, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Referrer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MediaType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs> : produce_base<D, Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *deferral = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Response(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(void), Windows::Web::Http::HttpResponseMessage const&);
            this->shim().Response(*reinterpret_cast<Windows::Web::Http::HttpResponseMessage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Response(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::UI {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::UI::IWebViewControl> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControl> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControl2> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControl2> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlContentLoadingEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlDeferredPermissionRequest> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlNavigationStartingEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlPermissionRequest> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlPermissionRequest> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlScriptNotifyEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlSettings> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlSettings> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlContentLoadingEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlDOMContentLoadedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlDeferredPermissionRequest> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlLongRunningScriptDetectedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlNavigationCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlNavigationStartingEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlNewWindowRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlPermissionRequest> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlPermissionRequest> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlPermissionRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlScriptNotifyEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlSettings> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlSettings> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlUnsupportedUriSchemeIdentifiedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlUnviewableContentIdentifiedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::WebViewControlWebResourceRequestedEventArgs> {};

}
