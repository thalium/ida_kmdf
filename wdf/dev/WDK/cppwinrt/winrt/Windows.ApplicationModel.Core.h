// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::AppDisplayInfo consume_Windows_ApplicationModel_Core_IAppListEntry<D>::DisplayInfo() const
{
    Windows::ApplicationModel::AppDisplayInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IAppListEntry)->get_DisplayInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Core_IAppListEntry<D>::LaunchAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IAppListEntry)->LaunchAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_Core_IAppListEntry2<D>::AppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IAppListEntry2)->get_AppUserModelId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Core_IAppListEntry3<D>::LaunchForUserAsync(Windows::System::User const& user) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IAppListEntry3)->LaunchForUserAsync(get_abi(user), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->get_Id(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Suspending(Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->add_Suspending(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Suspending_revoker consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Suspending(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Suspending_revoker>(this, Suspending(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Suspending(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->remove_Suspending(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Resuming(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->add_Resuming(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Resuming_revoker consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Resuming(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Resuming_revoker>(this, Resuming(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Resuming(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->remove_Resuming(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationView consume_Windows_ApplicationModel_Core_ICoreApplication<D>::GetCurrentView() const
{
    Windows::ApplicationModel::Core::CoreApplicationView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->GetCurrentView(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication<D>::Run(Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->Run(get_abi(viewSource)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication<D>::RunWithActivationFactories(Windows::Foundation::IGetActivationFactory const& activationFactoryCallback) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication)->RunWithActivationFactories(get_abi(activationFactoryCallback)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::BackgroundActivated(Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->add_BackgroundActivated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::BackgroundActivated_revoker consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::BackgroundActivated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BackgroundActivated_revoker>(this, BackgroundActivated(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::BackgroundActivated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->remove_BackgroundActivated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::LeavingBackground(Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->add_LeavingBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::LeavingBackground_revoker consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::LeavingBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LeavingBackground_revoker>(this, LeavingBackground(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::LeavingBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->remove_LeavingBackground(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::EnteredBackground(Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->add_EnteredBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::EnteredBackground_revoker consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::EnteredBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EnteredBackground_revoker>(this, EnteredBackground(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::EnteredBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->remove_EnteredBackground(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplication2<D>::EnablePrelaunch(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication2)->EnablePrelaunch(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> consume_Windows_ApplicationModel_Core_ICoreApplication3<D>::RequestRestartAsync(param::hstring const& launchArguments) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication3)->RequestRestartAsync(get_abi(launchArguments), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> consume_Windows_ApplicationModel_Core_ICoreApplication3<D>::RequestRestartForUserAsync(Windows::System::User const& user, param::hstring const& launchArguments) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplication3)->RequestRestartForUserAsync(get_abi(user), get_abi(launchArguments), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationExit<D>::Exit() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationExit)->Exit());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationExit<D>::Exiting(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationExit)->add_Exiting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationExit<D>::Exiting_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationExit<D>::Exiting(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Exiting_revoker>(this, Exiting(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationExit<D>::Exiting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationExit)->remove_Exiting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationUnhandledError<D>::UnhandledErrorDetected(Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationUnhandledError)->add_UnhandledErrorDetected(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationUnhandledError<D>::UnhandledErrorDetected_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationUnhandledError<D>::UnhandledErrorDetected(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UnhandledErrorDetected_revoker>(this, UnhandledErrorDetected(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationUnhandledError<D>::UnhandledErrorDetected(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationUnhandledError)->remove_UnhandledErrorDetected(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationUseCount<D>::IncrementApplicationUseCount() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationUseCount)->IncrementApplicationUseCount());
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationUseCount<D>::DecrementApplicationUseCount() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationUseCount)->DecrementApplicationUseCount());
}

template <typename D> Windows::UI::Core::CoreWindow consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::CoreWindow() const
{
    Windows::UI::Core::CoreWindow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView)->get_CoreWindow(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::Activated(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView)->add_Activated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::Activated_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::Activated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::Activated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView)->remove_Activated(get_abi(token)));
}

template <typename D> bool consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::IsMain() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView)->get_IsMain(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Core_ICoreApplicationView<D>::IsHosted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView)->get_IsHosted(&value));
    return value;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_ApplicationModel_Core_ICoreApplicationView2<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView2)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::IsComponent() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView3)->get_IsComponent(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationViewTitleBar consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::TitleBar() const
{
    Windows::ApplicationModel::Core::CoreApplicationViewTitleBar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView3)->get_TitleBar(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::HostedViewClosing(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Core::HostedViewClosingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView3)->add_HostedViewClosing(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::HostedViewClosing_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::HostedViewClosing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Core::HostedViewClosingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HostedViewClosing_revoker>(this, HostedViewClosing(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationView3<D>::HostedViewClosing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView3)->remove_HostedViewClosing(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_ApplicationModel_Core_ICoreApplicationView5<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView5)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_ApplicationModel_Core_ICoreApplicationView6<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationView6)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::ExtendViewIntoTitleBar(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->put_ExtendViewIntoTitleBar(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::ExtendViewIntoTitleBar() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->get_ExtendViewIntoTitleBar(&value));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::SystemOverlayLeftInset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->get_SystemOverlayLeftInset(&value));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::SystemOverlayRightInset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->get_SystemOverlayRightInset(&value));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::Height() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->get_Height(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::LayoutMetricsChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->add_LayoutMetricsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::LayoutMetricsChanged_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::LayoutMetricsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LayoutMetricsChanged_revoker>(this, LayoutMetricsChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::LayoutMetricsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->remove_LayoutMetricsChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->get_IsVisible(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::IsVisibleChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->add_IsVisibleChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::IsVisibleChanged_revoker consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::IsVisibleChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, IsVisibleChanged_revoker>(this, IsVisibleChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Core_ICoreApplicationViewTitleBar<D>::IsVisibleChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar)->remove_IsVisibleChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::CoreApplicationView> consume_Windows_ApplicationModel_Core_ICoreImmersiveApplication<D>::Views() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::CoreApplicationView> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreImmersiveApplication)->get_Views(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationView consume_Windows_ApplicationModel_Core_ICoreImmersiveApplication<D>::CreateNewView(param::hstring const& runtimeType, param::hstring const& entryPoint) const
{
    Windows::ApplicationModel::Core::CoreApplicationView view{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreImmersiveApplication)->CreateNewView(get_abi(runtimeType), get_abi(entryPoint), put_abi(view)));
    return view;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationView consume_Windows_ApplicationModel_Core_ICoreImmersiveApplication<D>::MainView() const
{
    Windows::ApplicationModel::Core::CoreApplicationView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreImmersiveApplication)->get_MainView(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationView consume_Windows_ApplicationModel_Core_ICoreImmersiveApplication2<D>::CreateNewView() const
{
    Windows::ApplicationModel::Core::CoreApplicationView view{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreImmersiveApplication2)->CreateNewViewFromMainView(put_abi(view)));
    return view;
}

template <typename D> Windows::ApplicationModel::Core::CoreApplicationView consume_Windows_ApplicationModel_Core_ICoreImmersiveApplication3<D>::CreateNewView(Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource) const
{
    Windows::ApplicationModel::Core::CoreApplicationView view{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::ICoreImmersiveApplication3)->CreateNewViewWithViewSource(get_abi(viewSource), put_abi(view)));
    return view;
}

template <typename D> void consume_Windows_ApplicationModel_Core_IFrameworkView<D>::Initialize(Windows::ApplicationModel::Core::CoreApplicationView const& applicationView) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkView)->Initialize(get_abi(applicationView)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_IFrameworkView<D>::SetWindow(Windows::UI::Core::CoreWindow const& window) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkView)->SetWindow(get_abi(window)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_IFrameworkView<D>::Load(param::hstring const& entryPoint) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkView)->Load(get_abi(entryPoint)));
}

template <typename D> void consume_Windows_ApplicationModel_Core_IFrameworkView<D>::Run() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkView)->Run());
}

template <typename D> void consume_Windows_ApplicationModel_Core_IFrameworkView<D>::Uninitialize() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkView)->Uninitialize());
}

template <typename D> Windows::ApplicationModel::Core::IFrameworkView consume_Windows_ApplicationModel_Core_IFrameworkViewSource<D>::CreateView() const
{
    Windows::ApplicationModel::Core::IFrameworkView viewProvider{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IFrameworkViewSource)->CreateView(put_abi(viewProvider)));
    return viewProvider;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Core_IHostedViewClosingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IHostedViewClosingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Core_IUnhandledError<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IUnhandledError)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Core_IUnhandledError<D>::Propagate() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IUnhandledError)->Propagate());
}

template <typename D> Windows::ApplicationModel::Core::UnhandledError consume_Windows_ApplicationModel_Core_IUnhandledErrorDetectedEventArgs<D>::UnhandledError() const
{
    Windows::ApplicationModel::Core::UnhandledError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Core::IUnhandledErrorDetectedEventArgs)->get_UnhandledError(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IAppListEntry> : produce_base<D, Windows::ApplicationModel::Core::IAppListEntry>
{
    int32_t WINRT_CALL get_DisplayInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayInfo, WINRT_WRAP(Windows::ApplicationModel::AppDisplayInfo));
            *value = detach_from<Windows::ApplicationModel::AppDisplayInfo>(this->shim().DisplayInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IAppListEntry2> : produce_base<D, Windows::ApplicationModel::Core::IAppListEntry2>
{
    int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppUserModelId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppUserModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IAppListEntry3> : produce_base<D, Windows::ApplicationModel::Core::IAppListEntry3>
{
    int32_t WINRT_CALL LaunchForUserAsync(void* user, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplication> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplication>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Suspending(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suspending, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Suspending(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(Resuming, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Resuming(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentView, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationView));
            *value = detach_from<Windows::ApplicationModel::Core::CoreApplicationView>(this->shim().GetCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Run(void* viewSource) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Run, WINRT_WRAP(void), Windows::ApplicationModel::Core::IFrameworkViewSource const&);
            this->shim().Run(*reinterpret_cast<Windows::ApplicationModel::Core::IFrameworkViewSource const*>(&viewSource));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunWithActivationFactories(void* activationFactoryCallback) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunWithActivationFactories, WINRT_WRAP(void), Windows::Foundation::IGetActivationFactory const&);
            this->shim().RunWithActivationFactories(*reinterpret_cast<Windows::Foundation::IGetActivationFactory const*>(&activationFactoryCallback));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplication2> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplication2>
{
    int32_t WINRT_CALL add_BackgroundActivated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundActivated, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BackgroundActivated(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_LeavingBackground(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeavingBackground, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LeavingBackground(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(EnteredBackground, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnteredBackground(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const*>(&handler)));
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
struct produce<D, Windows::ApplicationModel::Core::ICoreApplication3> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplication3>
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
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationExit> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationExit>
{
    int32_t WINRT_CALL Exit() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exit, WINRT_WRAP(void));
            this->shim().Exit();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Exiting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exiting, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Exiting(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Exiting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Exiting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Exiting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationUnhandledError> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationUnhandledError>
{
    int32_t WINRT_CALL add_UnhandledErrorDetected(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnhandledErrorDetected, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UnhandledErrorDetected(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UnhandledErrorDetected(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UnhandledErrorDetected, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UnhandledErrorDetected(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationUseCount> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationUseCount>
{
    int32_t WINRT_CALL IncrementApplicationUseCount() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncrementApplicationUseCount, WINRT_WRAP(void));
            this->shim().IncrementApplicationUseCount();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DecrementApplicationUseCount() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecrementApplicationUseCount, WINRT_WRAP(void));
            this->shim().DecrementApplicationUseCount();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationView> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationView>
{
    int32_t WINRT_CALL get_CoreWindow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoreWindow, WINRT_WRAP(Windows::UI::Core::CoreWindow));
            *value = detach_from<Windows::UI::Core::CoreWindow>(this->shim().CoreWindow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Activation::IActivatedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL get_IsMain(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMain, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHosted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHosted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHosted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationView2> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationView2>
{
    int32_t WINRT_CALL get_Dispatcher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dispatcher, WINRT_WRAP(Windows::UI::Core::CoreDispatcher));
            *value = detach_from<Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationView3> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationView3>
{
    int32_t WINRT_CALL get_IsComponent(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComponent, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsComponent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleBar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleBar, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationViewTitleBar));
            *value = detach_from<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar>(this->shim().TitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HostedViewClosing(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostedViewClosing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Core::HostedViewClosingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HostedViewClosing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationView, Windows::ApplicationModel::Core::HostedViewClosingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HostedViewClosing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HostedViewClosing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HostedViewClosing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationView5> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationView5>
{
    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationView6> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationView6>
{
    int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispatcherQueue, WINRT_WRAP(Windows::System::DispatcherQueue));
            *value = detach_from<Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar> : produce_base<D, Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar>
{
    int32_t WINRT_CALL put_ExtendViewIntoTitleBar(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendViewIntoTitleBar, WINRT_WRAP(void), bool);
            this->shim().ExtendViewIntoTitleBar(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendViewIntoTitleBar(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendViewIntoTitleBar, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExtendViewIntoTitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemOverlayLeftInset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemOverlayLeftInset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SystemOverlayLeftInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemOverlayRightInset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemOverlayRightInset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SystemOverlayRightInset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LayoutMetricsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LayoutMetricsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LayoutMetricsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LayoutMetricsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LayoutMetricsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LayoutMetricsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_IsVisibleChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisibleChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().IsVisibleChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Core::CoreApplicationViewTitleBar, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_IsVisibleChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(IsVisibleChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().IsVisibleChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication> : produce_base<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication>
{
    int32_t WINRT_CALL get_Views(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Views, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::CoreApplicationView>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::CoreApplicationView>>(this->shim().Views());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateNewView(void* runtimeType, void* entryPoint, void** view) noexcept final
    {
        try
        {
            *view = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNewView, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationView), hstring const&, hstring const&);
            *view = detach_from<Windows::ApplicationModel::Core::CoreApplicationView>(this->shim().CreateNewView(*reinterpret_cast<hstring const*>(&runtimeType), *reinterpret_cast<hstring const*>(&entryPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MainView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MainView, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationView));
            *value = detach_from<Windows::ApplicationModel::Core::CoreApplicationView>(this->shim().MainView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication2> : produce_base<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication2>
{
    int32_t WINRT_CALL CreateNewViewFromMainView(void** view) noexcept final
    {
        try
        {
            *view = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNewView, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationView));
            *view = detach_from<Windows::ApplicationModel::Core::CoreApplicationView>(this->shim().CreateNewView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication3> : produce_base<D, Windows::ApplicationModel::Core::ICoreImmersiveApplication3>
{
    int32_t WINRT_CALL CreateNewViewWithViewSource(void* viewSource, void** view) noexcept final
    {
        try
        {
            *view = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNewView, WINRT_WRAP(Windows::ApplicationModel::Core::CoreApplicationView), Windows::ApplicationModel::Core::IFrameworkViewSource const&);
            *view = detach_from<Windows::ApplicationModel::Core::CoreApplicationView>(this->shim().CreateNewView(*reinterpret_cast<Windows::ApplicationModel::Core::IFrameworkViewSource const*>(&viewSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IFrameworkView> : produce_base<D, Windows::ApplicationModel::Core::IFrameworkView>
{
    int32_t WINRT_CALL Initialize(void* applicationView) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Initialize, WINRT_WRAP(void), Windows::ApplicationModel::Core::CoreApplicationView const&);
            this->shim().Initialize(*reinterpret_cast<Windows::ApplicationModel::Core::CoreApplicationView const*>(&applicationView));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetWindow(void* window) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetWindow, WINRT_WRAP(void), Windows::UI::Core::CoreWindow const&);
            this->shim().SetWindow(*reinterpret_cast<Windows::UI::Core::CoreWindow const*>(&window));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Load(void* entryPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Load, WINRT_WRAP(void), hstring const&);
            this->shim().Load(*reinterpret_cast<hstring const*>(&entryPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Run() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Run, WINRT_WRAP(void));
            this->shim().Run();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Uninitialize() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uninitialize, WINRT_WRAP(void));
            this->shim().Uninitialize();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IFrameworkViewSource> : produce_base<D, Windows::ApplicationModel::Core::IFrameworkViewSource>
{
    int32_t WINRT_CALL CreateView(void** viewProvider) noexcept final
    {
        try
        {
            *viewProvider = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateView, WINRT_WRAP(Windows::ApplicationModel::Core::IFrameworkView));
            *viewProvider = detach_from<Windows::ApplicationModel::Core::IFrameworkView>(this->shim().CreateView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IHostedViewClosingEventArgs> : produce_base<D, Windows::ApplicationModel::Core::IHostedViewClosingEventArgs>
{
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
struct produce<D, Windows::ApplicationModel::Core::IUnhandledError> : produce_base<D, Windows::ApplicationModel::Core::IUnhandledError>
{
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

    int32_t WINRT_CALL Propagate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Propagate, WINRT_WRAP(void));
            this->shim().Propagate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Core::IUnhandledErrorDetectedEventArgs> : produce_base<D, Windows::ApplicationModel::Core::IUnhandledErrorDetectedEventArgs>
{
    int32_t WINRT_CALL get_UnhandledError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnhandledError, WINRT_WRAP(Windows::ApplicationModel::Core::UnhandledError));
            *value = detach_from<Windows::ApplicationModel::Core::UnhandledError>(this->shim().UnhandledError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

inline hstring CoreApplication::Id()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Id(); });
}

inline winrt::event_token CoreApplication::Suspending(Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Suspending(handler); });
}

inline CoreApplication::Suspending_revoker CoreApplication::Suspending(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::SuspendingEventArgs> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>();
    return { f, f.Suspending(handler) };
}

inline void CoreApplication::Suspending(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Suspending(token); });
}

inline winrt::event_token CoreApplication::Resuming(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Resuming(handler); });
}

inline CoreApplication::Resuming_revoker CoreApplication::Resuming(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>();
    return { f, f.Resuming(handler) };
}

inline void CoreApplication::Resuming(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Resuming(token); });
}

inline Windows::Foundation::Collections::IPropertySet CoreApplication::Properties()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Properties(); });
}

inline Windows::ApplicationModel::Core::CoreApplicationView CoreApplication::GetCurrentView()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.GetCurrentView(); });
}

inline void CoreApplication::Run(Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.Run(viewSource); });
}

inline void CoreApplication::RunWithActivationFactories(Windows::Foundation::IGetActivationFactory const& activationFactoryCallback)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication>([&](auto&& f) { return f.RunWithActivationFactories(activationFactoryCallback); });
}

inline winrt::event_token CoreApplication::BackgroundActivated(Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.BackgroundActivated(handler); });
}

inline CoreApplication::BackgroundActivated_revoker CoreApplication::BackgroundActivated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>();
    return { f, f.BackgroundActivated(handler) };
}

inline void CoreApplication::BackgroundActivated(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.BackgroundActivated(token); });
}

inline winrt::event_token CoreApplication::LeavingBackground(Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.LeavingBackground(handler); });
}

inline CoreApplication::LeavingBackground_revoker CoreApplication::LeavingBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::LeavingBackgroundEventArgs> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>();
    return { f, f.LeavingBackground(handler) };
}

inline void CoreApplication::LeavingBackground(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.LeavingBackground(token); });
}

inline winrt::event_token CoreApplication::EnteredBackground(Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.EnteredBackground(handler); });
}

inline CoreApplication::EnteredBackground_revoker CoreApplication::EnteredBackground(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::EnteredBackgroundEventArgs> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>();
    return { f, f.EnteredBackground(handler) };
}

inline void CoreApplication::EnteredBackground(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.EnteredBackground(token); });
}

inline void CoreApplication::EnablePrelaunch(bool value)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication2>([&](auto&& f) { return f.EnablePrelaunch(value); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> CoreApplication::RequestRestartAsync(param::hstring const& launchArguments)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication3>([&](auto&& f) { return f.RequestRestartAsync(launchArguments); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Core::AppRestartFailureReason> CoreApplication::RequestRestartForUserAsync(Windows::System::User const& user, param::hstring const& launchArguments)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplication3>([&](auto&& f) { return f.RequestRestartForUserAsync(user, launchArguments); });
}

inline void CoreApplication::Exit()
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationExit>([&](auto&& f) { return f.Exit(); });
}

inline winrt::event_token CoreApplication::Exiting(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationExit>([&](auto&& f) { return f.Exiting(handler); });
}

inline CoreApplication::Exiting_revoker CoreApplication::Exiting(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationExit>();
    return { f, f.Exiting(handler) };
}

inline void CoreApplication::Exiting(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationExit>([&](auto&& f) { return f.Exiting(token); });
}

inline winrt::event_token CoreApplication::UnhandledErrorDetected(Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationUnhandledError>([&](auto&& f) { return f.UnhandledErrorDetected(handler); });
}

inline CoreApplication::UnhandledErrorDetected_revoker CoreApplication::UnhandledErrorDetected(auto_revoke_t, Windows::Foundation::EventHandler<Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> const& handler)
{
    auto f = get_activation_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationUnhandledError>();
    return { f, f.UnhandledErrorDetected(handler) };
}

inline void CoreApplication::UnhandledErrorDetected(winrt::event_token const& token)
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationUnhandledError>([&](auto&& f) { return f.UnhandledErrorDetected(token); });
}

inline void CoreApplication::IncrementApplicationUseCount()
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationUseCount>([&](auto&& f) { return f.IncrementApplicationUseCount(); });
}

inline void CoreApplication::DecrementApplicationUseCount()
{
    impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreApplicationUseCount>([&](auto&& f) { return f.DecrementApplicationUseCount(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::CoreApplicationView> CoreApplication::Views()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreImmersiveApplication>([&](auto&& f) { return f.Views(); });
}

inline Windows::ApplicationModel::Core::CoreApplicationView CoreApplication::CreateNewView(param::hstring const& runtimeType, param::hstring const& entryPoint)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreImmersiveApplication>([&](auto&& f) { return f.CreateNewView(runtimeType, entryPoint); });
}

inline Windows::ApplicationModel::Core::CoreApplicationView CoreApplication::MainView()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreImmersiveApplication>([&](auto&& f) { return f.MainView(); });
}

inline Windows::ApplicationModel::Core::CoreApplicationView CoreApplication::CreateNewView()
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreImmersiveApplication2>([&](auto&& f) { return f.CreateNewView(); });
}

inline Windows::ApplicationModel::Core::CoreApplicationView CoreApplication::CreateNewView(Windows::ApplicationModel::Core::IFrameworkViewSource const& viewSource)
{
    return impl::call_factory<CoreApplication, Windows::ApplicationModel::Core::ICoreImmersiveApplication3>([&](auto&& f) { return f.CreateNewView(viewSource); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Core::IAppListEntry> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IAppListEntry> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IAppListEntry2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IAppListEntry2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IAppListEntry3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IAppListEntry3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplication> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplication> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplication2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplication2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplication3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplication3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationExit> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationExit> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationUnhandledError> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationUnhandledError> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationUseCount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationUseCount> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationView2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationView2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationView3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationView3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationView5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationView5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationView6> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationView6> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreApplicationViewTitleBar> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::ICoreImmersiveApplication3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IFrameworkView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IFrameworkView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IFrameworkViewSource> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IFrameworkViewSource> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IHostedViewClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IHostedViewClosingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IUnhandledError> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IUnhandledError> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::IUnhandledErrorDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::IUnhandledErrorDetectedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::AppListEntry> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::AppListEntry> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::CoreApplication> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::CoreApplication> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::CoreApplicationView> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::CoreApplicationView> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::CoreApplicationViewTitleBar> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::CoreApplicationViewTitleBar> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::HostedViewClosingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::HostedViewClosingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::UnhandledError> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::UnhandledError> {};
template<> struct hash<winrt::Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Core::UnhandledErrorDetectedEventArgs> {};

}
