// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::UI::UIContentRoot consume_Windows_UI_WindowManagement_IAppWindow<D>::Content() const
{
    Windows::UI::UIContentRoot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_UI_WindowManagement_IAppWindow<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::AppWindowFrame consume_Windows_UI_WindowManagement_IAppWindow<D>::Frame() const
{
    Windows::UI::WindowManagement::AppWindowFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindow<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_IsVisible(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_WindowManagement_IAppWindow<D>::PersistedStateId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_PersistedStateId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::PersistedStateId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->put_PersistedStateId(get_abi(value)));
}

template <typename D> Windows::UI::WindowManagement::AppWindowPresenter consume_Windows_UI_WindowManagement_IAppWindow<D>::Presenter() const
{
    Windows::UI::WindowManagement::AppWindowPresenter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_Presenter(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_WindowManagement_IAppWindow<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->put_Title(get_abi(value)));
}

template <typename D> Windows::UI::WindowManagement::AppWindowTitleBar consume_Windows_UI_WindowManagement_IAppWindow<D>::TitleBar() const
{
    Windows::UI::WindowManagement::AppWindowTitleBar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_TitleBar(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_WindowManagement_IAppWindow<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironment consume_Windows_UI_WindowManagement_IAppWindow<D>::WindowingEnvironment() const
{
    Windows::UI::WindowManagement::WindowingEnvironment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->get_WindowingEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->CloseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::WindowManagement::AppWindowPlacement consume_Windows_UI_WindowManagement_IAppWindow<D>::GetPlacement() const
{
    Windows::UI::WindowManagement::AppWindowPlacement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->GetPlacement(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> consume_Windows_UI_WindowManagement_IAppWindow<D>::GetDisplayRegions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->GetDisplayRegions(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveToDisplayRegion(Windows::UI::WindowManagement::DisplayRegion const& displayRegion) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveToDisplayRegion(get_abi(displayRegion)));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveAdjacentToCurrentView() const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveAdjacentToCurrentView());
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveAdjacentToWindow(Windows::UI::WindowManagement::AppWindow const& anchorWindow) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveAdjacentToWindow(get_abi(anchorWindow)));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToWindowContent(Windows::UI::WindowManagement::AppWindow const& anchorWindow, Windows::Foundation::Point const& contentOffset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToWindowContent(get_abi(anchorWindow), get_abi(contentOffset)));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToCurrentViewContent(Windows::Foundation::Point const& contentOffset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToCurrentViewContent(get_abi(contentOffset)));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestMoveRelativeToDisplayRegion(Windows::UI::WindowManagement::DisplayRegion const& displayRegion, Windows::Foundation::Point const& displayRegionOffset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestMoveRelativeToDisplayRegion(get_abi(displayRegion), get_abi(displayRegionOffset)));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::RequestSize(Windows::Foundation::Size const& frameSize) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->RequestSize(get_abi(frameSize)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_WindowManagement_IAppWindow<D>::TryShowAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->TryShowAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->remove_Changed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->add_CloseRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested_revoker consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CloseRequested_revoker>(this, CloseRequested(handler));
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindow<D>::CloseRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WindowManagement::IAppWindow)->remove_CloseRequested(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidAvailableWindowPresentationsChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidAvailableWindowPresentationsChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidDisplayRegionsChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidDisplayRegionsChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidFrameChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidFrameChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidSizeChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidSizeChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidTitleBarChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidTitleBarChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidVisibilityChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidVisibilityChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidWindowingEnvironmentChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidWindowingEnvironmentChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowChangedEventArgs<D>::DidWindowPresentationChange() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowChangedEventArgs)->get_DidWindowPresentationChange(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->put_Cancel(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_UI_WindowManagement_IAppWindowCloseRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::WindowManagement::AppWindowClosedReason consume_Windows_UI_WindowManagement_IAppWindowClosedEventArgs<D>::Reason() const
{
    Windows::UI::WindowManagement::AppWindowClosedReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowClosedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Composition::IVisualElement> consume_Windows_UI_WindowManagement_IAppWindowFrame<D>::DragRegionVisuals() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Composition::IVisualElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowFrame)->get_DragRegionVisuals(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::AppWindowFrameStyle consume_Windows_UI_WindowManagement_IAppWindowFrameStyle<D>::GetFrameStyle() const
{
    Windows::UI::WindowManagement::AppWindowFrameStyle result{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowFrameStyle)->GetFrameStyle(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowFrameStyle<D>::SetFrameStyle(Windows::UI::WindowManagement::AppWindowFrameStyle const& frameStyle) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowFrameStyle)->SetFrameStyle(get_abi(frameStyle)));
}

template <typename D> Windows::UI::WindowManagement::DisplayRegion consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::DisplayRegion() const
{
    Windows::UI::WindowManagement::DisplayRegion value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPlacement)->get_DisplayRegion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::Offset() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPlacement)->get_Offset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_WindowManagement_IAppWindowPlacement<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPlacement)->get_Size(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::AppWindowPresentationKind consume_Windows_UI_WindowManagement_IAppWindowPresentationConfiguration<D>::Kind() const
{
    Windows::UI::WindowManagement::AppWindowPresentationKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPresentationConfiguration)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::AppWindowPresentationConfiguration consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::GetConfiguration() const
{
    Windows::UI::WindowManagement::AppWindowPresentationConfiguration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPresenter)->GetConfiguration(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::IsPresentationSupported(Windows::UI::WindowManagement::AppWindowPresentationKind const& presentationKind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPresenter)->IsPresentationSupported(get_abi(presentationKind), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::RequestPresentation(Windows::UI::WindowManagement::AppWindowPresentationConfiguration const& configuration) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPresenter)->RequestPresentation(get_abi(configuration), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowPresenter<D>::RequestPresentation(Windows::UI::WindowManagement::AppWindowPresentationKind const& presentationKind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowPresenter)->RequestPresentationByKind(get_abi(presentationKind), &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow> consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::TryCreateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowStatics)->TryCreateAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::ClearAllPersistedState() const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowStatics)->ClearAllPersistedState());
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowStatics<D>::ClearPersistedState(param::hstring const& key) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowStatics)->ClearPersistedState(get_abi(key)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::BackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::BackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonHoverBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonHoverBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonHoverForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonHoverForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonHoverForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonInactiveBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonInactiveBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonInactiveForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonInactiveForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonInactiveForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonPressedBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonPressedBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ButtonPressedForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ButtonPressedForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ButtonPressedForegroundColor(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ExtendsContentIntoTitleBar() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ExtendsContentIntoTitleBar(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ExtendsContentIntoTitleBar(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ExtendsContentIntoTitleBar(value));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::ForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_InactiveBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_InactiveBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_InactiveForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::InactiveForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->put_InactiveForegroundColor(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->get_IsVisible(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::AppWindowTitleBarOcclusion> consume_Windows_UI_WindowManagement_IAppWindowTitleBar<D>::GetTitleBarOcclusions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::AppWindowTitleBarOcclusion> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBar)->GetTitleBarOcclusions(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_WindowManagement_IAppWindowTitleBarOcclusion<D>::OccludingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion)->get_OccludingRect(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::AppWindowTitleBarVisibility consume_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility<D>::GetPreferredVisibility() const
{
    Windows::UI::WindowManagement::AppWindowTitleBarVisibility result{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBarVisibility)->GetPreferredVisibility(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_WindowManagement_IAppWindowTitleBarVisibility<D>::SetPreferredVisibility(Windows::UI::WindowManagement::AppWindowTitleBarVisibility const& visibilityMode) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IAppWindowTitleBarVisibility)->SetPreferredVisibility(get_abi(visibilityMode)));
}

template <typename D> hstring consume_Windows_UI_WindowManagement_IDisplayRegion<D>::DisplayMonitorDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->get_DisplayMonitorDeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_WindowManagement_IDisplayRegion<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->get_IsVisible(&value));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WorkAreaOffset() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->get_WorkAreaOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WorkAreaSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->get_WorkAreaSize(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironment consume_Windows_UI_WindowManagement_IDisplayRegion<D>::WindowingEnvironment() const
{
    Windows::UI::WindowManagement::WindowingEnvironment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->get_WindowingEnvironment(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::DisplayRegion, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed_revoker consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::DisplayRegion, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_UI_WindowManagement_IDisplayRegion<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WindowManagement::IDisplayRegion)->remove_Changed(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration<D>::IsExclusive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IFullScreenPresentationConfiguration)->get_IsExclusive(&value));
    return value;
}

template <typename D> void consume_Windows_UI_WindowManagement_IFullScreenPresentationConfiguration<D>::IsExclusive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IFullScreenPresentationConfiguration)->put_IsExclusive(value));
}

template <typename D> bool consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironment)->get_IsEnabled(&value));
    return value;
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironmentKind consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Kind() const
{
    Windows::UI::WindowManagement::WindowingEnvironmentKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironment)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::GetDisplayRegions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironment)->GetDisplayRegions(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::WindowingEnvironment, Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironment)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed_revoker consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::WindowingEnvironment, Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_UI_WindowManagement_IWindowingEnvironment<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironment)->remove_Changed(get_abi(token)));
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironment consume_Windows_UI_WindowManagement_IWindowingEnvironmentAddedEventArgs<D>::WindowingEnvironment() const
{
    Windows::UI::WindowManagement::WindowingEnvironment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs)->get_WindowingEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironment consume_Windows_UI_WindowManagement_IWindowingEnvironmentRemovedEventArgs<D>::WindowingEnvironment() const
{
    Windows::UI::WindowManagement::WindowingEnvironment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs)->get_WindowingEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> consume_Windows_UI_WindowManagement_IWindowingEnvironmentStatics<D>::FindAll() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironmentStatics)->FindAll(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> consume_Windows_UI_WindowManagement_IWindowingEnvironmentStatics<D>::FindAll(Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::IWindowingEnvironmentStatics)->FindAllWithKind(get_abi(kind), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindow> : produce_base<D, Windows::UI::WindowManagement::IAppWindow>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::UI::UIContentRoot));
            *value = detach_from<Windows::UI::UIContentRoot>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowFrame));
            *value = detach_from<Windows::UI::WindowManagement::AppWindowFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
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

    int32_t WINRT_CALL get_PersistedStateId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PersistedStateId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PersistedStateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PersistedStateId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PersistedStateId, WINRT_WRAP(void), hstring const&);
            this->shim().PersistedStateId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Presenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Presenter, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowPresenter));
            *value = detach_from<Windows::UI::WindowManagement::AppWindowPresenter>(this->shim().Presenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(TitleBar, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowTitleBar));
            *value = detach_from<Windows::UI::WindowManagement::AppWindowTitleBar>(this->shim().TitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UIContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIContext, WINRT_WRAP(Windows::UI::UIContext));
            *value = detach_from<Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WindowingEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowingEnvironment, WINRT_WRAP(Windows::UI::WindowManagement::WindowingEnvironment));
            *value = detach_from<Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CloseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CloseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPlacement(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPlacement, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowPlacement));
            *result = detach_from<Windows::UI::WindowManagement::AppWindowPlacement>(this->shim().GetPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDisplayRegions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDisplayRegions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion>>(this->shim().GetDisplayRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveToDisplayRegion(void* displayRegion) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveToDisplayRegion, WINRT_WRAP(void), Windows::UI::WindowManagement::DisplayRegion const&);
            this->shim().RequestMoveToDisplayRegion(*reinterpret_cast<Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveAdjacentToCurrentView() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveAdjacentToCurrentView, WINRT_WRAP(void));
            this->shim().RequestMoveAdjacentToCurrentView();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveAdjacentToWindow(void* anchorWindow) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveAdjacentToWindow, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindow const&);
            this->shim().RequestMoveAdjacentToWindow(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&anchorWindow));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveRelativeToWindowContent(void* anchorWindow, Windows::Foundation::Point contentOffset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveRelativeToWindowContent, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindow const&, Windows::Foundation::Point const&);
            this->shim().RequestMoveRelativeToWindowContent(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&anchorWindow), *reinterpret_cast<Windows::Foundation::Point const*>(&contentOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveRelativeToCurrentViewContent(Windows::Foundation::Point contentOffset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveRelativeToCurrentViewContent, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().RequestMoveRelativeToCurrentViewContent(*reinterpret_cast<Windows::Foundation::Point const*>(&contentOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMoveRelativeToDisplayRegion(void* displayRegion, Windows::Foundation::Point displayRegionOffset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMoveRelativeToDisplayRegion, WINRT_WRAP(void), Windows::UI::WindowManagement::DisplayRegion const&, Windows::Foundation::Point const&);
            this->shim().RequestMoveRelativeToDisplayRegion(*reinterpret_cast<Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion), *reinterpret_cast<Windows::Foundation::Point const*>(&displayRegionOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSize(Windows::Foundation::Size frameSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().RequestSize(*reinterpret_cast<Windows::Foundation::Size const*>(&frameSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowClosedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_CloseRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CloseRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::AppWindow, Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CloseRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CloseRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CloseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowChangedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IAppWindowChangedEventArgs>
{
    int32_t WINRT_CALL get_DidAvailableWindowPresentationsChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidAvailableWindowPresentationsChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidAvailableWindowPresentationsChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidDisplayRegionsChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidDisplayRegionsChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidDisplayRegionsChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidFrameChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidFrameChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidFrameChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidSizeChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidSizeChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidSizeChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidTitleBarChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidTitleBarChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidTitleBarChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidVisibilityChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidVisibilityChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidVisibilityChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidWindowingEnvironmentChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidWindowingEnvironmentChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidWindowingEnvironmentChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DidWindowPresentationChange(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DidWindowPresentationChange, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DidWindowPresentationChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs>
{
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
struct produce<D, Windows::UI::WindowManagement::IAppWindowClosedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IAppWindowClosedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::UI::WindowManagement::AppWindowClosedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowClosedReason));
            *value = detach_from<Windows::UI::WindowManagement::AppWindowClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowFrame> : produce_base<D, Windows::UI::WindowManagement::IAppWindowFrame>
{
    int32_t WINRT_CALL get_DragRegionVisuals(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragRegionVisuals, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Composition::IVisualElement>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Composition::IVisualElement>>(this->shim().DragRegionVisuals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowFrameStyle> : produce_base<D, Windows::UI::WindowManagement::IAppWindowFrameStyle>
{
    int32_t WINRT_CALL GetFrameStyle(Windows::UI::WindowManagement::AppWindowFrameStyle* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFrameStyle, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowFrameStyle));
            *result = detach_from<Windows::UI::WindowManagement::AppWindowFrameStyle>(this->shim().GetFrameStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFrameStyle(Windows::UI::WindowManagement::AppWindowFrameStyle frameStyle) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFrameStyle, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindowFrameStyle const&);
            this->shim().SetFrameStyle(*reinterpret_cast<Windows::UI::WindowManagement::AppWindowFrameStyle const*>(&frameStyle));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowPlacement> : produce_base<D, Windows::UI::WindowManagement::IAppWindowPlacement>
{
    int32_t WINRT_CALL get_DisplayRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayRegion, WINRT_WRAP(Windows::UI::WindowManagement::DisplayRegion));
            *value = detach_from<Windows::UI::WindowManagement::DisplayRegion>(this->shim().DisplayRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Offset(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Offset, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Offset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowPresentationConfiguration> : produce_base<D, Windows::UI::WindowManagement::IAppWindowPresentationConfiguration>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::WindowManagement::AppWindowPresentationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowPresentationKind));
            *value = detach_from<Windows::UI::WindowManagement::AppWindowPresentationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory> : produce_base<D, Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory>
{};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowPresenter> : produce_base<D, Windows::UI::WindowManagement::IAppWindowPresenter>
{
    int32_t WINRT_CALL GetConfiguration(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConfiguration, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowPresentationConfiguration));
            *result = detach_from<Windows::UI::WindowManagement::AppWindowPresentationConfiguration>(this->shim().GetConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPresentationSupported(Windows::UI::WindowManagement::AppWindowPresentationKind presentationKind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPresentationSupported, WINRT_WRAP(bool), Windows::UI::WindowManagement::AppWindowPresentationKind const&);
            *result = detach_from<bool>(this->shim().IsPresentationSupported(*reinterpret_cast<Windows::UI::WindowManagement::AppWindowPresentationKind const*>(&presentationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPresentation(void* configuration, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPresentation, WINRT_WRAP(bool), Windows::UI::WindowManagement::AppWindowPresentationConfiguration const&);
            *result = detach_from<bool>(this->shim().RequestPresentation(*reinterpret_cast<Windows::UI::WindowManagement::AppWindowPresentationConfiguration const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPresentationByKind(Windows::UI::WindowManagement::AppWindowPresentationKind presentationKind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPresentation, WINRT_WRAP(bool), Windows::UI::WindowManagement::AppWindowPresentationKind const&);
            *result = detach_from<bool>(this->shim().RequestPresentation(*reinterpret_cast<Windows::UI::WindowManagement::AppWindowPresentationKind const*>(&presentationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowStatics> : produce_base<D, Windows::UI::WindowManagement::IAppWindowStatics>
{
    int32_t WINRT_CALL TryCreateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow>>(this->shim().TryCreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAllPersistedState() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAllPersistedState, WINRT_WRAP(void));
            this->shim().ClearAllPersistedState();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearPersistedState(void* key) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearPersistedState, WINRT_WRAP(void), hstring const&);
            this->shim().ClearPersistedState(*reinterpret_cast<hstring const*>(&key));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowTitleBar> : produce_base<D, Windows::UI::WindowManagement::IAppWindowTitleBar>
{
    int32_t WINRT_CALL get_BackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonBackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonBackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonBackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonBackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonBackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonHoverBackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonHoverBackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonHoverBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonHoverBackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonHoverBackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonHoverBackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonHoverForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonHoverForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonHoverForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonHoverForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonHoverForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonHoverForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonInactiveBackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonInactiveBackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonInactiveBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonInactiveBackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonInactiveBackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonInactiveBackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonInactiveForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonInactiveForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonInactiveForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonInactiveForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonInactiveForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonInactiveForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonPressedBackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressedBackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonPressedBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonPressedBackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressedBackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonPressedBackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ButtonPressedForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressedForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ButtonPressedForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ButtonPressedForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ButtonPressedForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ButtonPressedForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendsContentIntoTitleBar(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendsContentIntoTitleBar, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExtendsContentIntoTitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExtendsContentIntoTitleBar(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendsContentIntoTitleBar, WINRT_WRAP(void), bool);
            this->shim().ExtendsContentIntoTitleBar(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InactiveBackgroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InactiveBackgroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().InactiveBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InactiveBackgroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InactiveBackgroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().InactiveBackgroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InactiveForegroundColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InactiveForegroundColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().InactiveForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InactiveForegroundColor(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InactiveForegroundColor, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().InactiveForegroundColor(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
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

    int32_t WINRT_CALL GetTitleBarOcclusions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTitleBarOcclusions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::AppWindowTitleBarOcclusion>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::AppWindowTitleBarOcclusion>>(this->shim().GetTitleBarOcclusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion> : produce_base<D, Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion>
{
    int32_t WINRT_CALL get_OccludingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OccludingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OccludingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IAppWindowTitleBarVisibility> : produce_base<D, Windows::UI::WindowManagement::IAppWindowTitleBarVisibility>
{
    int32_t WINRT_CALL GetPreferredVisibility(Windows::UI::WindowManagement::AppWindowTitleBarVisibility* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreferredVisibility, WINRT_WRAP(Windows::UI::WindowManagement::AppWindowTitleBarVisibility));
            *result = detach_from<Windows::UI::WindowManagement::AppWindowTitleBarVisibility>(this->shim().GetPreferredVisibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreferredVisibility(Windows::UI::WindowManagement::AppWindowTitleBarVisibility visibilityMode) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreferredVisibility, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindowTitleBarVisibility const&);
            this->shim().SetPreferredVisibility(*reinterpret_cast<Windows::UI::WindowManagement::AppWindowTitleBarVisibility const*>(&visibilityMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration> : produce_base<D, Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IDefaultPresentationConfiguration> : produce_base<D, Windows::UI::WindowManagement::IDefaultPresentationConfiguration>
{};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IDisplayRegion> : produce_base<D, Windows::UI::WindowManagement::IDisplayRegion>
{
    int32_t WINRT_CALL get_DisplayMonitorDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMonitorDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayMonitorDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
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

    int32_t WINRT_CALL get_WorkAreaOffset(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorkAreaOffset, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().WorkAreaOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WorkAreaSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorkAreaSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().WorkAreaSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WindowingEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowingEnvironment, WINRT_WRAP(Windows::UI::WindowManagement::WindowingEnvironment));
            *value = detach_from<Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::DisplayRegion, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::DisplayRegion, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IFullScreenPresentationConfiguration> : produce_base<D, Windows::UI::WindowManagement::IFullScreenPresentationConfiguration>
{
    int32_t WINRT_CALL get_IsExclusive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExclusive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsExclusive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsExclusive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExclusive, WINRT_WRAP(void), bool);
            this->shim().IsExclusive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IWindowingEnvironment> : produce_base<D, Windows::UI::WindowManagement::IWindowingEnvironment>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::UI::WindowManagement::WindowingEnvironmentKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::WindowManagement::WindowingEnvironmentKind));
            *value = detach_from<Windows::UI::WindowManagement::WindowingEnvironmentKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDisplayRegions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDisplayRegions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion>>(this->shim().GetDisplayRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::WindowingEnvironment, Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::WindowManagement::WindowingEnvironment, Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs>
{
    int32_t WINRT_CALL get_WindowingEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowingEnvironment, WINRT_WRAP(Windows::UI::WindowManagement::WindowingEnvironment));
            *value = detach_from<Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs> : produce_base<D, Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs>
{
    int32_t WINRT_CALL get_WindowingEnvironment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowingEnvironment, WINRT_WRAP(Windows::UI::WindowManagement::WindowingEnvironment));
            *value = detach_from<Windows::UI::WindowManagement::WindowingEnvironment>(this->shim().WindowingEnvironment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::IWindowingEnvironmentStatics> : produce_base<D, Windows::UI::WindowManagement::IWindowingEnvironmentStatics>
{
    int32_t WINRT_CALL FindAll(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment>>(this->shim().FindAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllWithKind(Windows::UI::WindowManagement::WindowingEnvironmentKind kind, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment>), Windows::UI::WindowManagement::WindowingEnvironmentKind const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment>>(this->shim().FindAll(*reinterpret_cast<Windows::UI::WindowManagement::WindowingEnvironmentKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement {

inline Windows::Foundation::IAsyncOperation<Windows::UI::WindowManagement::AppWindow> AppWindow::TryCreateAsync()
{
    return impl::call_factory<AppWindow, Windows::UI::WindowManagement::IAppWindowStatics>([&](auto&& f) { return f.TryCreateAsync(); });
}

inline void AppWindow::ClearAllPersistedState()
{
    impl::call_factory<AppWindow, Windows::UI::WindowManagement::IAppWindowStatics>([&](auto&& f) { return f.ClearAllPersistedState(); });
}

inline void AppWindow::ClearPersistedState(param::hstring const& key)
{
    impl::call_factory<AppWindow, Windows::UI::WindowManagement::IAppWindowStatics>([&](auto&& f) { return f.ClearPersistedState(key); });
}

inline CompactOverlayPresentationConfiguration::CompactOverlayPresentationConfiguration() :
    CompactOverlayPresentationConfiguration(impl::call_factory<CompactOverlayPresentationConfiguration>([](auto&& f) { return f.template ActivateInstance<CompactOverlayPresentationConfiguration>(); }))
{}

inline DefaultPresentationConfiguration::DefaultPresentationConfiguration() :
    DefaultPresentationConfiguration(impl::call_factory<DefaultPresentationConfiguration>([](auto&& f) { return f.template ActivateInstance<DefaultPresentationConfiguration>(); }))
{}

inline FullScreenPresentationConfiguration::FullScreenPresentationConfiguration() :
    FullScreenPresentationConfiguration(impl::call_factory<FullScreenPresentationConfiguration>([](auto&& f) { return f.template ActivateInstance<FullScreenPresentationConfiguration>(); }))
{}

inline Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> WindowingEnvironment::FindAll()
{
    return impl::call_factory<WindowingEnvironment, Windows::UI::WindowManagement::IWindowingEnvironmentStatics>([&](auto&& f) { return f.FindAll(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::WindowingEnvironment> WindowingEnvironment::FindAll(Windows::UI::WindowManagement::WindowingEnvironmentKind const& kind)
{
    return impl::call_factory<WindowingEnvironment, Windows::UI::WindowManagement::IWindowingEnvironmentStatics>([&](auto&& f) { return f.FindAll(kind); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindow> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindow> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowCloseRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowClosedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowFrame> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowFrame> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowFrameStyle> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPlacement> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowPlacement> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowPresentationConfigurationFactory> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowPresenter> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowPresenter> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowStatics> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowStatics> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBar> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowTitleBar> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarOcclusion> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IAppWindowTitleBarVisibility> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::ICompactOverlayPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IDefaultPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IDisplayRegion> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IDisplayRegion> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IFullScreenPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironment> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IWindowingEnvironment> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentAddedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentRemovedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::IWindowingEnvironmentStatics> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindow> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindow> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowCloseRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowClosedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowFrame> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowFrame> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPlacement> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowPlacement> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowPresenter> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowPresenter> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowTitleBar> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowTitleBar> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::AppWindowTitleBarOcclusion> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::CompactOverlayPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::CompactOverlayPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::DefaultPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::DefaultPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::DisplayRegion> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::DisplayRegion> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::FullScreenPresentationConfiguration> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::FullScreenPresentationConfiguration> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironment> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::WindowingEnvironment> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::WindowingEnvironmentAddedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::WindowingEnvironmentChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::WindowingEnvironmentRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::WindowingEnvironmentRemovedEventArgs> {};

}
