// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.AppointmentsProvider.2.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.Provider.2.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.2.h"
#include "winrt/impl/Windows.ApplicationModel.Search.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.Provider.2.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Devices.Printers.Extensions.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.SpeechRecognition.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Provider.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Pickers.Provider.2.h"
#include "winrt/impl/Windows.Storage.Provider.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.UI.2.h"
#include "winrt/impl/Windows.Graphics.Printing.2.h"
#include "winrt/impl/Windows.UI.WebUI.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> void consume_Windows_UI_WebUI_IActivatedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IActivatedDeferral)->Complete());
}

template <typename D> Windows::UI::WebUI::ActivatedOperation consume_Windows_UI_WebUI_IActivatedEventArgsDeferral<D>::ActivatedOperation() const
{
    Windows::UI::WebUI::ActivatedOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IActivatedEventArgsDeferral)->get_ActivatedOperation(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WebUI::ActivatedDeferral consume_Windows_UI_WebUI_IActivatedOperation<D>::GetDeferral() const
{
    Windows::UI::WebUI::ActivatedDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IActivatedOperation)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> Windows::UI::WebUI::PrintContent consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::Content() const
{
    Windows::UI::WebUI::PrintContent value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::Content(Windows::UI::WebUI::PrintContent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_Content(get_abi(value)));
}

template <typename D> float consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::LeftMargin() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_LeftMargin(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::LeftMargin(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_LeftMargin(value));
}

template <typename D> float consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::TopMargin() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_TopMargin(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::TopMargin(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_TopMargin(value));
}

template <typename D> float consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::RightMargin() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_RightMargin(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::RightMargin(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_RightMargin(value));
}

template <typename D> float consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::BottomMargin() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_BottomMargin(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::BottomMargin(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_BottomMargin(value));
}

template <typename D> bool consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::EnableHeaderFooter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_EnableHeaderFooter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::EnableHeaderFooter(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_EnableHeaderFooter(value));
}

template <typename D> bool consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::ShrinkToFit() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_ShrinkToFit(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::ShrinkToFit(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_ShrinkToFit(value));
}

template <typename D> float consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::PercentScale() const
{
    float pScalePercent{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_PercentScale(&pScalePercent));
    return pScalePercent;
}

template <typename D> void consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::PercentScale(float scalePercent) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->put_PercentScale(scalePercent));
}

template <typename D> hstring consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::PageRange() const
{
    hstring pstrPageRange{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->get_PageRange(put_abi(pstrPageRange)));
    return pstrPageRange;
}

template <typename D> bool consume_Windows_UI_WebUI_IHtmlPrintDocumentSource<D>::TrySetPageRange(param::hstring const& strPageRange) const
{
    bool pfSuccess{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IHtmlPrintDocumentSource)->TrySetPageRange(get_abi(strPageRange), &pfSuccess));
    return pfSuccess;
}

template <typename D> Windows::UI::WebUI::WebUIView consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs<D>::WebUIView() const
{
    Windows::UI::WebUI::WebUIView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::INewWebUIViewCreatedEventArgs)->get_WebUIView(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Activation::IActivatedEventArgs consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs<D>::ActivatedEventArgs() const
{
    Windows::ApplicationModel::Activation::IActivatedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::INewWebUIViewCreatedEventArgs)->get_ActivatedEventArgs(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs<D>::HasPendingNavigate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::INewWebUIViewCreatedEventArgs)->get_HasPendingNavigate(&value));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_UI_WebUI_INewWebUIViewCreatedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::INewWebUIViewCreatedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Activated(Windows::UI::WebUI::ActivatedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->add_Activated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Activated_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Activated(auto_revoke_t, Windows::UI::WebUI::ActivatedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Activated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->remove_Activated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Suspending(Windows::UI::WebUI::SuspendingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->add_Suspending(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Suspending_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Suspending(auto_revoke_t, Windows::UI::WebUI::SuspendingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Suspending_revoker>(this, Suspending(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Suspending(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->remove_Suspending(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Resuming(Windows::UI::WebUI::ResumingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->add_Resuming(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Resuming_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Resuming(auto_revoke_t, Windows::UI::WebUI::ResumingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Resuming_revoker>(this, Resuming(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Resuming(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->remove_Resuming(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Navigated(Windows::UI::WebUI::NavigatedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->add_Navigated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Navigated_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Navigated(auto_revoke_t, Windows::UI::WebUI::NavigatedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Navigated_revoker>(this, Navigated(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics<D>::Navigated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics)->remove_Navigated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::LeavingBackground(Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics2)->add_LeavingBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::LeavingBackground_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::LeavingBackground(auto_revoke_t, Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LeavingBackground_revoker>(this, LeavingBackground(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::LeavingBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics2)->remove_LeavingBackground(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::EnteredBackground(Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics2)->add_EnteredBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::EnteredBackground_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::EnteredBackground(auto_revoke_t, Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler) const
{
    return impl::make_event_revoker<D, EnteredBackground_revoker>(this, EnteredBackground(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::EnteredBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics2)->remove_EnteredBackground(get_abi(token)));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics2<D>::EnablePrelaunch(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics2)->EnablePrelaunch(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> consume_Windows_UI_WebUI_IWebUIActivationStatics3<D>::RequestRestartAsync(param::hstring const& launchArguments) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics3)->RequestRestartAsync(get_abi(launchArguments), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> consume_Windows_UI_WebUI_IWebUIActivationStatics3<D>::RequestRestartForUserAsync(Windows::System::User const& user, param::hstring const& launchArguments) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics3)->RequestRestartForUserAsync(get_abi(user), get_abi(launchArguments), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::NewWebUIViewCreated(Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics4)->add_NewWebUIViewCreated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::NewWebUIViewCreated_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::NewWebUIViewCreated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NewWebUIViewCreated_revoker>(this, NewWebUIViewCreated(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::NewWebUIViewCreated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics4)->remove_NewWebUIViewCreated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::BackgroundActivated(Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics4)->add_BackgroundActivated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::BackgroundActivated_revoker consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::BackgroundActivated(auto_revoke_t, Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, BackgroundActivated_revoker>(this, BackgroundActivated(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIActivationStatics4<D>::BackgroundActivated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIActivationStatics4)->remove_BackgroundActivated(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstance<D>::Succeeded() const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIBackgroundTaskInstance)->get_Succeeded(&succeeded));
    return succeeded;
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstance<D>::Succeeded(bool succeeded) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIBackgroundTaskInstance)->put_Succeeded(succeeded));
}

template <typename D> Windows::UI::WebUI::IWebUIBackgroundTaskInstance consume_Windows_UI_WebUI_IWebUIBackgroundTaskInstanceStatics<D>::Current() const
{
    Windows::UI::WebUI::IWebUIBackgroundTaskInstance backgroundTaskInstance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics)->get_Current(put_abi(backgroundTaskInstance)));
    return backgroundTaskInstance;
}

template <typename D> void consume_Windows_UI_WebUI_IWebUINavigatedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUINavigatedDeferral)->Complete());
}

template <typename D> Windows::UI::WebUI::WebUINavigatedOperation consume_Windows_UI_WebUI_IWebUINavigatedEventArgs<D>::NavigatedOperation() const
{
    Windows::UI::WebUI::WebUINavigatedOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUINavigatedEventArgs)->get_NavigatedOperation(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WebUI::WebUINavigatedDeferral consume_Windows_UI_WebUI_IWebUINavigatedOperation<D>::GetDeferral() const
{
    Windows::UI::WebUI::WebUINavigatedDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUINavigatedOperation)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> int32_t consume_Windows_UI_WebUI_IWebUIView<D>::ApplicationViewId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->get_ApplicationViewId(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIView<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIView<D>::Closed_revoker consume_Windows_UI_WebUI_IWebUIView<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIView<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WebUI_IWebUIView<D>::Activated(Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->add_Activated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WebUI_IWebUIView<D>::Activated_revoker consume_Windows_UI_WebUI_IWebUIView<D>::Activated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIView<D>::Activated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->remove_Activated(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WebUI_IWebUIView<D>::IgnoreApplicationContentUriRulesNavigationRestrictions() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->get_IgnoreApplicationContentUriRulesNavigationRestrictions(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WebUI_IWebUIView<D>::IgnoreApplicationContentUriRulesNavigationRestrictions(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIView)->put_IgnoreApplicationContentUriRulesNavigationRestrictions(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> consume_Windows_UI_WebUI_IWebUIViewStatics<D>::CreateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIViewStatics)->CreateAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> consume_Windows_UI_WebUI_IWebUIViewStatics<D>::CreateAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WebUI::IWebUIViewStatics)->CreateWithUriAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <> struct delegate<Windows::UI::WebUI::ActivatedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::ActivatedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::ActivatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* eventArgs) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::Activation::IActivatedEventArgs const*>(&eventArgs));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::BackgroundActivatedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::BackgroundActivatedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::BackgroundActivatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* eventArgs) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs const*>(&eventArgs));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::EnteredBackgroundEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::EnteredBackgroundEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::EnteredBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::IEnteredBackgroundEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::LeavingBackgroundEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::LeavingBackgroundEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::LeavingBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::ILeavingBackgroundEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::NavigatedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::NavigatedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::NavigatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::WebUI::IWebUINavigatedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::ResumingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::ResumingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::ResumingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::WebUI::SuspendingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::WebUI::SuspendingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::WebUI::SuspendingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::ISuspendingEventArgs const*>(&e));
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
struct produce<D, Windows::UI::WebUI::IActivatedDeferral> : produce_base<D, Windows::UI::WebUI::IActivatedDeferral>
{
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
struct produce<D, Windows::UI::WebUI::IActivatedEventArgsDeferral> : produce_base<D, Windows::UI::WebUI::IActivatedEventArgsDeferral>
{
    int32_t WINRT_CALL get_ActivatedOperation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatedOperation, WINRT_WRAP(Windows::UI::WebUI::ActivatedOperation));
            *value = detach_from<Windows::UI::WebUI::ActivatedOperation>(this->shim().ActivatedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IActivatedOperation> : produce_base<D, Windows::UI::WebUI::IActivatedOperation>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::WebUI::ActivatedDeferral));
            *deferral = detach_from<Windows::UI::WebUI::ActivatedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IHtmlPrintDocumentSource> : produce_base<D, Windows::UI::WebUI::IHtmlPrintDocumentSource>
{
    int32_t WINRT_CALL get_Content(Windows::UI::WebUI::PrintContent* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::UI::WebUI::PrintContent));
            *value = detach_from<Windows::UI::WebUI::PrintContent>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(Windows::UI::WebUI::PrintContent value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), Windows::UI::WebUI::PrintContent const&);
            this->shim().Content(*reinterpret_cast<Windows::UI::WebUI::PrintContent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftMargin(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftMargin, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LeftMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LeftMargin(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftMargin, WINRT_WRAP(void), float);
            this->shim().LeftMargin(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TopMargin(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopMargin, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().TopMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TopMargin(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TopMargin, WINRT_WRAP(void), float);
            this->shim().TopMargin(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightMargin(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightMargin, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RightMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightMargin(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightMargin, WINRT_WRAP(void), float);
            this->shim().RightMargin(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BottomMargin(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomMargin, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BottomMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BottomMargin(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BottomMargin, WINRT_WRAP(void), float);
            this->shim().BottomMargin(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnableHeaderFooter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableHeaderFooter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableHeaderFooter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableHeaderFooter(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableHeaderFooter, WINRT_WRAP(void), bool);
            this->shim().EnableHeaderFooter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShrinkToFit(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShrinkToFit, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShrinkToFit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShrinkToFit(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShrinkToFit, WINRT_WRAP(void), bool);
            this->shim().ShrinkToFit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PercentScale(float* pScalePercent) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentScale, WINRT_WRAP(float));
            *pScalePercent = detach_from<float>(this->shim().PercentScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PercentScale(float scalePercent) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentScale, WINRT_WRAP(void), float);
            this->shim().PercentScale(scalePercent);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageRange(void** pstrPageRange) noexcept final
    {
        try
        {
            *pstrPageRange = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageRange, WINRT_WRAP(hstring));
            *pstrPageRange = detach_from<hstring>(this->shim().PageRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetPageRange(void* strPageRange, bool* pfSuccess) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetPageRange, WINRT_WRAP(bool), hstring const&);
            *pfSuccess = detach_from<bool>(this->shim().TrySetPageRange(*reinterpret_cast<hstring const*>(&strPageRange)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::INewWebUIViewCreatedEventArgs> : produce_base<D, Windows::UI::WebUI::INewWebUIViewCreatedEventArgs>
{
    int32_t WINRT_CALL get_WebUIView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebUIView, WINRT_WRAP(Windows::UI::WebUI::WebUIView));
            *value = detach_from<Windows::UI::WebUI::WebUIView>(this->shim().WebUIView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivatedEventArgs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivatedEventArgs, WINRT_WRAP(Windows::ApplicationModel::Activation::IActivatedEventArgs));
            *value = detach_from<Windows::ApplicationModel::Activation::IActivatedEventArgs>(this->shim().ActivatedEventArgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasPendingNavigate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasPendingNavigate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasPendingNavigate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIActivationStatics> : produce_base<D, Windows::UI::WebUI::IWebUIActivationStatics>
{
    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::ActivatedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::UI::WebUI::ActivatedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Activated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Suspending(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suspending, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::SuspendingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Suspending(*reinterpret_cast<Windows::UI::WebUI::SuspendingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Suspending(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Suspending, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Suspending(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Resuming(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resuming, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::ResumingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Resuming(*reinterpret_cast<Windows::UI::WebUI::ResumingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Resuming(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Resuming, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Resuming(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Navigated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Navigated, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::NavigatedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Navigated(*reinterpret_cast<Windows::UI::WebUI::NavigatedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Navigated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Navigated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Navigated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIActivationStatics2> : produce_base<D, Windows::UI::WebUI::IWebUIActivationStatics2>
{
    int32_t WINRT_CALL add_LeavingBackground(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeavingBackground, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::LeavingBackgroundEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LeavingBackground(*reinterpret_cast<Windows::UI::WebUI::LeavingBackgroundEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LeavingBackground(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LeavingBackground, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LeavingBackground(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnteredBackground(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnteredBackground, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::EnteredBackgroundEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().EnteredBackground(*reinterpret_cast<Windows::UI::WebUI::EnteredBackgroundEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnteredBackground(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnteredBackground, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnteredBackground(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL EnablePrelaunch(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnablePrelaunch, WINRT_WRAP(void), bool);
            this->shim().EnablePrelaunch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIActivationStatics3> : produce_base<D, Windows::UI::WebUI::IWebUIActivationStatics3>
{
    int32_t WINRT_CALL RequestRestartAsync(void* launchArguments, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRestartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason>>(this->shim().RequestRestartAsync(*reinterpret_cast<hstring const*>(&launchArguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestRestartForUserAsync(void* user, void* launchArguments, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRestartForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason>>(this->shim().RequestRestartForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&launchArguments)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIActivationStatics4> : produce_base<D, Windows::UI::WebUI::IWebUIActivationStatics4>
{
    int32_t WINRT_CALL add_NewWebUIViewCreated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewWebUIViewCreated, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NewWebUIViewCreated(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NewWebUIViewCreated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NewWebUIViewCreated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NewWebUIViewCreated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BackgroundActivated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundActivated, WINRT_WRAP(winrt::event_token), Windows::UI::WebUI::BackgroundActivatedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().BackgroundActivated(*reinterpret_cast<Windows::UI::WebUI::BackgroundActivatedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BackgroundActivated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BackgroundActivated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BackgroundActivated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIBackgroundTaskInstance> : produce_base<D, Windows::UI::WebUI::IWebUIBackgroundTaskInstance>
{
    int32_t WINRT_CALL get_Succeeded(bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *succeeded = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Succeeded(bool succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(void), bool);
            this->shim().Succeeded(succeeded);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics> : produce_base<D, Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>
{
    int32_t WINRT_CALL get_Current(void** backgroundTaskInstance) noexcept final
    {
        try
        {
            *backgroundTaskInstance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::UI::WebUI::IWebUIBackgroundTaskInstance));
            *backgroundTaskInstance = detach_from<Windows::UI::WebUI::IWebUIBackgroundTaskInstance>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUINavigatedDeferral> : produce_base<D, Windows::UI::WebUI::IWebUINavigatedDeferral>
{
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
struct produce<D, Windows::UI::WebUI::IWebUINavigatedEventArgs> : produce_base<D, Windows::UI::WebUI::IWebUINavigatedEventArgs>
{
    int32_t WINRT_CALL get_NavigatedOperation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigatedOperation, WINRT_WRAP(Windows::UI::WebUI::WebUINavigatedOperation));
            *value = detach_from<Windows::UI::WebUI::WebUINavigatedOperation>(this->shim().NavigatedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUINavigatedOperation> : produce_base<D, Windows::UI::WebUI::IWebUINavigatedOperation>
{
    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::WebUI::WebUINavigatedDeferral));
            *deferral = detach_from<Windows::UI::WebUI::WebUINavigatedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIView> : produce_base<D, Windows::UI::WebUI::IWebUIView>
{
    int32_t WINRT_CALL get_ApplicationViewId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationViewId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ApplicationViewId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WebUI::WebUIView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Activated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Activated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IgnoreApplicationContentUriRulesNavigationRestrictions(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreApplicationContentUriRulesNavigationRestrictions, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnoreApplicationContentUriRulesNavigationRestrictions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnoreApplicationContentUriRulesNavigationRestrictions(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreApplicationContentUriRulesNavigationRestrictions, WINRT_WRAP(void), bool);
            this->shim().IgnoreApplicationContentUriRulesNavigationRestrictions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WebUI::IWebUIViewStatics> : produce_base<D, Windows::UI::WebUI::IWebUIViewStatics>
{
    int32_t WINRT_CALL CreateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView>>(this->shim().CreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithUriAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView>>(this->shim().CreateAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::WebUI {

inline winrt::event_token WebUIApplication::Activated(Windows::UI::WebUI::ActivatedEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Activated(handler); });
}

inline WebUIApplication::Activated_revoker WebUIApplication::Activated(auto_revoke_t, Windows::UI::WebUI::ActivatedEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>();
    return { f, f.Activated(handler) };
}

inline void WebUIApplication::Activated(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Activated(token); });
}

inline winrt::event_token WebUIApplication::Suspending(Windows::UI::WebUI::SuspendingEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Suspending(handler); });
}

inline WebUIApplication::Suspending_revoker WebUIApplication::Suspending(auto_revoke_t, Windows::UI::WebUI::SuspendingEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>();
    return { f, f.Suspending(handler) };
}

inline void WebUIApplication::Suspending(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Suspending(token); });
}

inline winrt::event_token WebUIApplication::Resuming(Windows::UI::WebUI::ResumingEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Resuming(handler); });
}

inline WebUIApplication::Resuming_revoker WebUIApplication::Resuming(auto_revoke_t, Windows::UI::WebUI::ResumingEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>();
    return { f, f.Resuming(handler) };
}

inline void WebUIApplication::Resuming(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Resuming(token); });
}

inline winrt::event_token WebUIApplication::Navigated(Windows::UI::WebUI::NavigatedEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Navigated(handler); });
}

inline WebUIApplication::Navigated_revoker WebUIApplication::Navigated(auto_revoke_t, Windows::UI::WebUI::NavigatedEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>();
    return { f, f.Navigated(handler) };
}

inline void WebUIApplication::Navigated(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics>([&](auto&& f) { return f.Navigated(token); });
}

inline winrt::event_token WebUIApplication::LeavingBackground(Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>([&](auto&& f) { return f.LeavingBackground(handler); });
}

inline WebUIApplication::LeavingBackground_revoker WebUIApplication::LeavingBackground(auto_revoke_t, Windows::UI::WebUI::LeavingBackgroundEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>();
    return { f, f.LeavingBackground(handler) };
}

inline void WebUIApplication::LeavingBackground(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>([&](auto&& f) { return f.LeavingBackground(token); });
}

inline winrt::event_token WebUIApplication::EnteredBackground(Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>([&](auto&& f) { return f.EnteredBackground(handler); });
}

inline WebUIApplication::EnteredBackground_revoker WebUIApplication::EnteredBackground(auto_revoke_t, Windows::UI::WebUI::EnteredBackgroundEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>();
    return { f, f.EnteredBackground(handler) };
}

inline void WebUIApplication::EnteredBackground(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>([&](auto&& f) { return f.EnteredBackground(token); });
}

inline void WebUIApplication::EnablePrelaunch(bool value)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics2>([&](auto&& f) { return f.EnablePrelaunch(value); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> WebUIApplication::RequestRestartAsync(param::hstring const& launchArguments)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics3>([&](auto&& f) { return f.RequestRestartAsync(launchArguments); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> WebUIApplication::RequestRestartForUserAsync(Windows::System::User const& user, param::hstring const& launchArguments)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics3>([&](auto&& f) { return f.RequestRestartForUserAsync(user, launchArguments); });
}

inline winrt::event_token WebUIApplication::NewWebUIViewCreated(Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>([&](auto&& f) { return f.NewWebUIViewCreated(handler); });
}

inline WebUIApplication::NewWebUIViewCreated_revoker WebUIApplication::NewWebUIViewCreated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>();
    return { f, f.NewWebUIViewCreated(handler) };
}

inline void WebUIApplication::NewWebUIViewCreated(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>([&](auto&& f) { return f.NewWebUIViewCreated(token); });
}

inline winrt::event_token WebUIApplication::BackgroundActivated(Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler)
{
    return impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>([&](auto&& f) { return f.BackgroundActivated(handler); });
}

inline WebUIApplication::BackgroundActivated_revoker WebUIApplication::BackgroundActivated(auto_revoke_t, Windows::UI::WebUI::BackgroundActivatedEventHandler const& handler)
{
    auto f = get_activation_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>();
    return { f, f.BackgroundActivated(handler) };
}

inline void WebUIApplication::BackgroundActivated(winrt::event_token const& token)
{
    impl::call_factory<WebUIApplication, Windows::UI::WebUI::IWebUIActivationStatics4>([&](auto&& f) { return f.BackgroundActivated(token); });
}

inline Windows::UI::WebUI::IWebUIBackgroundTaskInstance WebUIBackgroundTaskInstance::Current()
{
    return impl::call_factory<WebUIBackgroundTaskInstance, Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics>([&](auto&& f) { return f.Current(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> WebUIView::CreateAsync()
{
    return impl::call_factory<WebUIView, Windows::UI::WebUI::IWebUIViewStatics>([&](auto&& f) { return f.CreateAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::WebUI::WebUIView> WebUIView::CreateAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<WebUIView, Windows::UI::WebUI::IWebUIViewStatics>([&](auto&& f) { return f.CreateAsync(uri); });
}

template <typename L> ActivatedEventHandler::ActivatedEventHandler(L handler) :
    ActivatedEventHandler(impl::make_delegate<ActivatedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ActivatedEventHandler::ActivatedEventHandler(F* handler) :
    ActivatedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ActivatedEventHandler::ActivatedEventHandler(O* object, M method) :
    ActivatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ActivatedEventHandler::ActivatedEventHandler(com_ptr<O>&& object, M method) :
    ActivatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ActivatedEventHandler::ActivatedEventHandler(weak_ref<O>&& object, M method) :
    ActivatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ActivatedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::Activation::IActivatedEventArgs const& eventArgs) const
{
    check_hresult((*(impl::abi_t<ActivatedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(eventArgs)));
}

template <typename L> BackgroundActivatedEventHandler::BackgroundActivatedEventHandler(L handler) :
    BackgroundActivatedEventHandler(impl::make_delegate<BackgroundActivatedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> BackgroundActivatedEventHandler::BackgroundActivatedEventHandler(F* handler) :
    BackgroundActivatedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> BackgroundActivatedEventHandler::BackgroundActivatedEventHandler(O* object, M method) :
    BackgroundActivatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> BackgroundActivatedEventHandler::BackgroundActivatedEventHandler(com_ptr<O>&& object, M method) :
    BackgroundActivatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> BackgroundActivatedEventHandler::BackgroundActivatedEventHandler(weak_ref<O>&& object, M method) :
    BackgroundActivatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void BackgroundActivatedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::Activation::IBackgroundActivatedEventArgs const& eventArgs) const
{
    check_hresult((*(impl::abi_t<BackgroundActivatedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(eventArgs)));
}

template <typename L> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(L handler) :
    EnteredBackgroundEventHandler(impl::make_delegate<EnteredBackgroundEventHandler>(std::forward<L>(handler)))
{}

template <typename F> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(F* handler) :
    EnteredBackgroundEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(O* object, M method) :
    EnteredBackgroundEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(com_ptr<O>&& object, M method) :
    EnteredBackgroundEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> EnteredBackgroundEventHandler::EnteredBackgroundEventHandler(weak_ref<O>&& object, M method) :
    EnteredBackgroundEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void EnteredBackgroundEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::IEnteredBackgroundEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<EnteredBackgroundEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(L handler) :
    LeavingBackgroundEventHandler(impl::make_delegate<LeavingBackgroundEventHandler>(std::forward<L>(handler)))
{}

template <typename F> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(F* handler) :
    LeavingBackgroundEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(O* object, M method) :
    LeavingBackgroundEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(com_ptr<O>&& object, M method) :
    LeavingBackgroundEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> LeavingBackgroundEventHandler::LeavingBackgroundEventHandler(weak_ref<O>&& object, M method) :
    LeavingBackgroundEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void LeavingBackgroundEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::ILeavingBackgroundEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<LeavingBackgroundEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> NavigatedEventHandler::NavigatedEventHandler(L handler) :
    NavigatedEventHandler(impl::make_delegate<NavigatedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NavigatedEventHandler::NavigatedEventHandler(F* handler) :
    NavigatedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(O* object, M method) :
    NavigatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(com_ptr<O>&& object, M method) :
    NavigatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NavigatedEventHandler::NavigatedEventHandler(weak_ref<O>&& object, M method) :
    NavigatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NavigatedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::WebUI::IWebUINavigatedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<NavigatedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ResumingEventHandler::ResumingEventHandler(L handler) :
    ResumingEventHandler(impl::make_delegate<ResumingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ResumingEventHandler::ResumingEventHandler(F* handler) :
    ResumingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ResumingEventHandler::ResumingEventHandler(O* object, M method) :
    ResumingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ResumingEventHandler::ResumingEventHandler(com_ptr<O>&& object, M method) :
    ResumingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ResumingEventHandler::ResumingEventHandler(weak_ref<O>&& object, M method) :
    ResumingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ResumingEventHandler::operator()(Windows::Foundation::IInspectable const& sender) const
{
    check_hresult((*(impl::abi_t<ResumingEventHandler>**)this)->Invoke(get_abi(sender)));
}

template <typename L> SuspendingEventHandler::SuspendingEventHandler(L handler) :
    SuspendingEventHandler(impl::make_delegate<SuspendingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> SuspendingEventHandler::SuspendingEventHandler(F* handler) :
    SuspendingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(O* object, M method) :
    SuspendingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(com_ptr<O>&& object, M method) :
    SuspendingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SuspendingEventHandler::SuspendingEventHandler(weak_ref<O>&& object, M method) :
    SuspendingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SuspendingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::ISuspendingEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<SuspendingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::WebUI::IActivatedDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IActivatedDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IActivatedEventArgsDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::IActivatedOperation> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IActivatedOperation> {};
template<> struct hash<winrt::Windows::UI::WebUI::IHtmlPrintDocumentSource> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IHtmlPrintDocumentSource> {};
template<> struct hash<winrt::Windows::UI::WebUI::INewWebUIViewCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::INewWebUIViewCreatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIActivationStatics> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIActivationStatics> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIActivationStatics2> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIActivationStatics2> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIActivationStatics3> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIActivationStatics3> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIActivationStatics4> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIActivationStatics4> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstance> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstance> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIBackgroundTaskInstanceStatics> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUINavigatedDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUINavigatedDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUINavigatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUINavigatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUINavigatedOperation> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUINavigatedOperation> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIView> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIView> {};
template<> struct hash<winrt::Windows::UI::WebUI::IWebUIViewStatics> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::IWebUIViewStatics> {};
template<> struct hash<winrt::Windows::UI::WebUI::ActivatedDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::ActivatedDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::ActivatedOperation> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::ActivatedOperation> {};
template<> struct hash<winrt::Windows::UI::WebUI::BackgroundActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::BackgroundActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::EnteredBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::EnteredBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::HtmlPrintDocumentSource> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::HtmlPrintDocumentSource> {};
template<> struct hash<winrt::Windows::UI::WebUI::LeavingBackgroundEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::LeavingBackgroundEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::NewWebUIViewCreatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::SuspendingDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::SuspendingDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::SuspendingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::SuspendingEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::SuspendingOperation> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::SuspendingOperation> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIApplication> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIApplication> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderAddAppointmentActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderAddAppointmentActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderRemoveAppointmentActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderReplaceAppointmentActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderShowAppointmentDetailsActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIAppointmentsProviderShowTimeFrameActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIBackgroundTaskInstance> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIBackgroundTaskInstance> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIBackgroundTaskInstanceRuntimeClass> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIBackgroundTaskInstanceRuntimeClass> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIBarcodeScannerPreviewActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIBarcodeScannerPreviewActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUICachedFileUpdaterActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUICachedFileUpdaterActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUICameraSettingsActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUICameraSettingsActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUICommandLineActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUICommandLineActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactCallActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactCallActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactMapActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactMapActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactMessageActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactMessageActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactPanelActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactPanelActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactPickerActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactPickerActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactPostActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactPostActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIContactVideoCallActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIContactVideoCallActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIDeviceActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIDeviceActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIDevicePairingActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIDevicePairingActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIDialReceiverActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIDialReceiverActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFileActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFileActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFileOpenPickerActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFileOpenPickerActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFileOpenPickerContinuationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFileOpenPickerContinuationEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFileSavePickerActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFileSavePickerActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFileSavePickerContinuationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFileSavePickerContinuationEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIFolderPickerContinuationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIFolderPickerContinuationEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUILaunchActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUILaunchActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUILockScreenActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUILockScreenActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUILockScreenCallActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUILockScreenCallActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUILockScreenComponentActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUILockScreenComponentActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUINavigatedDeferral> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUINavigatedDeferral> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUINavigatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUINavigatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUINavigatedOperation> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUINavigatedOperation> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIPrint3DWorkflowActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIPrint3DWorkflowActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIPrintTaskSettingsActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIPrintTaskSettingsActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIPrintWorkflowForegroundTaskActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIPrintWorkflowForegroundTaskActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIProtocolActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIProtocolActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIProtocolForResultsActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIProtocolForResultsActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIRestrictedLaunchActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIRestrictedLaunchActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUISearchActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUISearchActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIShareTargetActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIShareTargetActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIStartupTaskActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIStartupTaskActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIToastNotificationActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIToastNotificationActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIUserDataAccountProviderActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIUserDataAccountProviderActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIView> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIView> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIVoiceCommandActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIVoiceCommandActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIWalletActionActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIWalletActionActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIWebAccountProviderActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIWebAccountProviderActivatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WebUI::WebUIWebAuthenticationBrokerContinuationEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WebUI::WebUIWebAuthenticationBrokerContinuationEventArgs> {};

}
