// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Hosting.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_UI_Xaml_Hosting_IDesignerAppExitedEventArgs<D>::ExitCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs)->get_ExitCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::AppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManager)->get_AppUserModelId(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManager)->add_DesignerAppExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited_revoker consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DesignerAppExited_revoker>(this, DesignerAppExited(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::DesignerAppExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManager)->remove_DesignerAppExited(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Hosting::DesignerAppView> consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::CreateNewViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState const& initialViewState, Windows::Foundation::Size const& initialViewSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Hosting::DesignerAppView> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManager)->CreateNewViewAsync(get_abi(initialViewState), get_abi(initialViewSize), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Hosting_IDesignerAppManager<D>::LoadObjectIntoAppAsync(param::hstring const& dllName, winrt::guid const& classId, param::hstring const& initializationData) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManager)->LoadObjectIntoAppAsync(get_abi(dllName), get_abi(classId), get_abi(initializationData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Hosting::DesignerAppManager consume_Windows_UI_Xaml_Hosting_IDesignerAppManagerFactory<D>::Create(param::hstring const& appUserModelId) const
{
    Windows::UI::Xaml::Hosting::DesignerAppManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory)->Create(get_abi(appUserModelId), put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ApplicationViewId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ApplicationViewId(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::AppUserModelId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppView)->get_AppUserModelId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::DesignerAppViewState consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ViewState() const
{
    Windows::UI::Xaml::Hosting::DesignerAppViewState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ViewState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::ViewSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppView)->get_ViewSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Hosting_IDesignerAppView<D>::UpdateViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState const& viewState, Windows::Foundation::Size const& viewSize) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesignerAppView)->UpdateViewAsync(get_abi(viewState), get_abi(viewSize), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::Content() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::Content(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->put_Content(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::HasFocus() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->get_HasFocus(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->add_TakeFocusRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested_revoker consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TakeFocusRequested_revoker>(this, TakeFocusRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::TakeFocusRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->remove_TakeFocusRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus_revoker consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->remove_GotFocus(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSource<D>::NavigateFocus(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const& request) const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource)->NavigateFocus(get_abi(request), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Hosting::DesktopWindowXamlSource consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Hosting::DesktopWindowXamlSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceGotFocusEventArgs<D>::Request() const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest consume_Windows_UI_Xaml_Hosting_IDesktopWindowXamlSourceTakeFocusRequestedEventArgs<D>::Request() const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetElementVisual(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Composition::Visual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetElementVisual(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Composition::Visual consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetElementChildVisual(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Composition::Visual result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetElementChildVisual(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::SetElementChildVisual(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::Visual const& visual) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->SetElementChildVisual(get_abi(element), get_abi(visual)));
}

template <typename D> Windows::UI::Composition::CompositionPropertySet consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics<D>::GetScrollViewerManipulationPropertySet(Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer) const
{
    Windows::UI::Composition::CompositionPropertySet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics)->GetScrollViewerManipulationPropertySet(get_abi(scrollViewer), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetImplicitShowAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetImplicitShowAnimation(get_abi(element), get_abi(animation)));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetImplicitHideAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetImplicitHideAnimation(get_abi(element), get_abi(animation)));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::SetIsTranslationEnabled(Windows::UI::Xaml::UIElement const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->SetIsTranslationEnabled(get_abi(element), value));
}

template <typename D> Windows::UI::Composition::CompositionPropertySet consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics2<D>::GetPointerPositionPropertySet(Windows::UI::Xaml::UIElement const& targetElement) const
{
    Windows::UI::Composition::CompositionPropertySet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2)->GetPointerPositionPropertySet(get_abi(targetElement), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3<D>::SetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow, Windows::UI::Xaml::UIElement const& xamlContent) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3)->SetAppWindowContent(get_abi(appWindow), get_abi(xamlContent)));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Hosting_IElementCompositionPreviewStatics3<D>::GetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3)->GetAppWindowContent(get_abi(appWindow), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Hosting::WindowsXamlManager consume_Windows_UI_Xaml_Hosting_IWindowsXamlManagerStatics<D>::InitializeForCurrentThread() const
{
    Windows::UI::Xaml::Hosting::WindowsXamlManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics)->InitializeForCurrentThread(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::Reason() const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::HintRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_HintRect(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequest<D>::CorrelationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstance(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason) const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstance(get_abi(reason), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstanceWithHintRect(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect) const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstanceWithHintRect(get_abi(reason), get_abi(hintRect), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationRequestFactory<D>::CreateInstanceWithHintRectAndCorrelationId(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId) const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory)->CreateInstanceWithHintRectAndCorrelationId(get_abi(reason), get_abi(hintRect), get_abi(correlationId), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResult<D>::WasFocusMoved() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult)->get_WasFocusMoved(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult consume_Windows_UI_Xaml_Hosting_IXamlSourceFocusNavigationResultFactory<D>::CreateInstance(bool focusMoved) const
{
    Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory)->CreateInstance(focusMoved, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::RootElement() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_RootElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::RootElement(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_RootElement(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeKey() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_ThemeKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeKey(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_ThemeKey(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeResourcesXaml() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->get_ThemeResourcesXaml(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::ThemeResourcesXaml(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->put_ThemeResourcesXaml(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::SetSize(int32_t width, int32_t height) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->SetSize(width, height));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::Render() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->Render());
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenter<D>::Present() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenter)->Present());
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost<D>::ResolveFileResource(param::hstring const& path) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost)->ResolveFileResource(get_abi(path), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost2<D>::GetGenericXamlFilePath() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2)->GetGenericXamlFilePath(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterHost3<D>::ResolveDictionaryResource(Windows::UI::Xaml::ResourceDictionary const& dictionary, Windows::Foundation::IInspectable const& dictionaryKey, Windows::Foundation::IInspectable const& suggestedValue) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3)->ResolveDictionaryResource(get_abi(dictionary), get_abi(dictionaryKey), get_abi(suggestedValue), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::CompleteTimelinesAutomatically() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->get_CompleteTimelinesAutomatically(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::CompleteTimelinesAutomatically(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->put_CompleteTimelinesAutomatically(value));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::SetHost(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->SetHost(get_abi(host)));
}

template <typename D> void consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics<D>::NotifyWindowSizeChanged() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics)->NotifyWindowSizeChanged());
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2<D>::GetFlyoutPlacementTargetInfo(Windows::UI::Xaml::FrameworkElement const& placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks) const
{
    Windows::Foundation::Rect returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2)->GetFlyoutPlacementTargetInfo(get_abi(placementTarget), get_abi(preferredPlacement), put_abi(targetPreferredPlacement), &allowFallbacks, put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Hosting_IXamlUIPresenterStatics2<D>::GetFlyoutPlacement(Windows::Foundation::Rect const& placementTargetBounds, Windows::Foundation::Size const& controlSize, Windows::Foundation::Size const& minControlSize, Windows::Foundation::Rect const& containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement) const
{
    Windows::Foundation::Rect returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2)->GetFlyoutPlacement(get_abi(placementTargetBounds), get_abi(controlSize), get_abi(minControlSize), get_abi(containerRect), get_abi(targetPreferredPlacement), allowFallbacks, put_abi(chosenPlacement), put_abi(returnValue)));
    return returnValue;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> : produce_base<D, Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs>
{
    int32_t WINRT_CALL get_ExitCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExitCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesignerAppManager> : produce_base<D, Windows::UI::Xaml::Hosting::IDesignerAppManager>
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

    int32_t WINRT_CALL add_DesignerAppExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesignerAppExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DesignerAppExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesignerAppManager, Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DesignerAppExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DesignerAppExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DesignerAppExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateNewViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState initialViewState, Windows::Foundation::Size initialViewSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateNewViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Hosting::DesignerAppView>), Windows::UI::Xaml::Hosting::DesignerAppViewState const, Windows::Foundation::Size const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Hosting::DesignerAppView>>(this->shim().CreateNewViewAsync(*reinterpret_cast<Windows::UI::Xaml::Hosting::DesignerAppViewState const*>(&initialViewState), *reinterpret_cast<Windows::Foundation::Size const*>(&initialViewSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadObjectIntoAppAsync(void* dllName, winrt::guid classId, void* initializationData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadObjectIntoAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, winrt::guid const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LoadObjectIntoAppAsync(*reinterpret_cast<hstring const*>(&dllName), *reinterpret_cast<winrt::guid const*>(&classId), *reinterpret_cast<hstring const*>(&initializationData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> : produce_base<D, Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>
{
    int32_t WINRT_CALL Create(void* appUserModelId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Xaml::Hosting::DesignerAppManager), hstring const&);
            *value = detach_from<Windows::UI::Xaml::Hosting::DesignerAppManager>(this->shim().Create(*reinterpret_cast<hstring const*>(&appUserModelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesignerAppView> : produce_base<D, Windows::UI::Xaml::Hosting::IDesignerAppView>
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

    int32_t WINRT_CALL get_ViewState(Windows::UI::Xaml::Hosting::DesignerAppViewState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewState, WINRT_WRAP(Windows::UI::Xaml::Hosting::DesignerAppViewState));
            *value = detach_from<Windows::UI::Xaml::Hosting::DesignerAppViewState>(this->shim().ViewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().ViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateViewAsync(Windows::UI::Xaml::Hosting::DesignerAppViewState viewState, Windows::Foundation::Size viewSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Xaml::Hosting::DesignerAppViewState const, Windows::Foundation::Size const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateViewAsync(*reinterpret_cast<Windows::UI::Xaml::Hosting::DesignerAppViewState const*>(&viewState), *reinterpret_cast<Windows::Foundation::Size const*>(&viewSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> : produce_base<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Content(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasFocus(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasFocus, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TakeFocusRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TakeFocusRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TakeFocusRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TakeFocusRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TakeFocusRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TakeFocusRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NavigateFocus(void* request, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateFocus, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult), Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const&);
            *result = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>(this->shim().NavigateFocus(*reinterpret_cast<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> : produce_base<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Hosting::DesktopWindowXamlSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> : produce_base<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest));
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest));
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IElementCompositionPreview> : produce_base<D, Windows::UI::Xaml::Hosting::IElementCompositionPreview>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> : produce_base<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>
{
    int32_t WINRT_CALL GetElementVisual(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetElementVisual, WINRT_WRAP(Windows::UI::Composition::Visual), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Composition::Visual>(this->shim().GetElementVisual(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetElementChildVisual(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetElementChildVisual, WINRT_WRAP(Windows::UI::Composition::Visual), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Composition::Visual>(this->shim().GetElementChildVisual(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetElementChildVisual(void* element, void* visual) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetElementChildVisual, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, Windows::UI::Composition::Visual const&);
            this->shim().SetElementChildVisual(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<Windows::UI::Composition::Visual const*>(&visual));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScrollViewerManipulationPropertySet(void* scrollViewer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScrollViewerManipulationPropertySet, WINRT_WRAP(Windows::UI::Composition::CompositionPropertySet), Windows::UI::Xaml::Controls::ScrollViewer const&);
            *result = detach_from<Windows::UI::Composition::CompositionPropertySet>(this->shim().GetScrollViewerManipulationPropertySet(*reinterpret_cast<Windows::UI::Xaml::Controls::ScrollViewer const*>(&scrollViewer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> : produce_base<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>
{
    int32_t WINRT_CALL SetImplicitShowAnimation(void* element, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetImplicitShowAnimation, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().SetImplicitShowAnimation(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetImplicitHideAnimation(void* element, void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetImplicitHideAnimation, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().SetImplicitHideAnimation(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), *reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsTranslationEnabled(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsTranslationEnabled, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&, bool);
            this->shim().SetIsTranslationEnabled(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPointerPositionPropertySet(void* targetElement, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPointerPositionPropertySet, WINRT_WRAP(Windows::UI::Composition::CompositionPropertySet), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Composition::CompositionPropertySet>(this->shim().GetPointerPositionPropertySet(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&targetElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> : produce_base<D, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>
{
    int32_t WINRT_CALL SetAppWindowContent(void* appWindow, void* xamlContent) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAppWindowContent, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindow const&, Windows::UI::Xaml::UIElement const&);
            this->shim().SetAppWindowContent(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&appWindow), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&xamlContent));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppWindowContent(void* appWindow, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppWindowContent, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::UI::WindowManagement::AppWindow const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().GetAppWindowContent(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&appWindow)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IWindowsXamlManager> : produce_base<D, Windows::UI::Xaml::Hosting::IWindowsXamlManager>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> : produce_base<D, Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>
{
    int32_t WINRT_CALL InitializeForCurrentThread(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeForCurrentThread, WINRT_WRAP(Windows::UI::Xaml::Hosting::WindowsXamlManager));
            *result = detach_from<Windows::UI::Xaml::Hosting::WindowsXamlManager>(this->shim().InitializeForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest>
{
    int32_t WINRT_CALL get_Reason(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason));
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HintRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HintRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().HintRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CorrelationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest), Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const&);
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithHintRect(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, Windows::Foundation::Rect hintRect, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithHintRect, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest), Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const&, Windows::Foundation::Rect const&);
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstanceWithHintRect(*reinterpret_cast<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason), *reinterpret_cast<Windows::Foundation::Rect const*>(&hintRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithHintRectAndCorrelationId(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason reason, Windows::Foundation::Rect hintRect, winrt::guid correlationId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithHintRectAndCorrelationId, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest), Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const&, Windows::Foundation::Rect const&, winrt::guid const&);
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest>(this->shim().CreateInstanceWithHintRectAndCorrelationId(*reinterpret_cast<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const*>(&reason), *reinterpret_cast<Windows::Foundation::Rect const*>(&hintRect), *reinterpret_cast<winrt::guid const*>(&correlationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult>
{
    int32_t WINRT_CALL get_WasFocusMoved(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasFocusMoved, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasFocusMoved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>
{
    int32_t WINRT_CALL CreateInstance(bool focusMoved, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult), bool);
            *value = detach_from<Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult>(this->shim().CreateInstance(focusMoved));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenter> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenter>
{
    int32_t WINRT_CALL get_RootElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RootElement, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().RootElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RootElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RootElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().RootElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThemeKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThemeKey, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ThemeKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThemeKey(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThemeKey, WINRT_WRAP(void), hstring const&);
            this->shim().ThemeKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThemeResourcesXaml(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThemeResourcesXaml, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ThemeResourcesXaml());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThemeResourcesXaml(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThemeResourcesXaml, WINRT_WRAP(void), hstring const&);
            this->shim().ThemeResourcesXaml(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSize(int32_t width, int32_t height) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSize, WINRT_WRAP(void), int32_t, int32_t);
            this->shim().SetSize(width, height);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Render() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Render, WINRT_WRAP(void));
            this->shim().Render();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Present() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Present, WINRT_WRAP(void));
            this->shim().Present();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost>
{
    int32_t WINRT_CALL ResolveFileResource(void* path, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveFileResource, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().ResolveFileResource(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2>
{
    int32_t WINRT_CALL GetGenericXamlFilePath(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGenericXamlFilePath, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetGenericXamlFilePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3>
{
    int32_t WINRT_CALL ResolveDictionaryResource(void* dictionary, void* dictionaryKey, void* suggestedValue, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveDictionaryResource, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::ResourceDictionary const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ResolveDictionaryResource(*reinterpret_cast<Windows::UI::Xaml::ResourceDictionary const*>(&dictionary), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&dictionaryKey), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&suggestedValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>
{
    int32_t WINRT_CALL get_CompleteTimelinesAutomatically(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteTimelinesAutomatically, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CompleteTimelinesAutomatically());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompleteTimelinesAutomatically(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteTimelinesAutomatically, WINRT_WRAP(void), bool);
            this->shim().CompleteTimelinesAutomatically(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHost(void* host) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHost, WINRT_WRAP(void), Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const&);
            this->shim().SetHost(*reinterpret_cast<Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const*>(&host));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyWindowSizeChanged() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyWindowSizeChanged, WINRT_WRAP(void));
            this->shim().NotifyWindowSizeChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> : produce_base<D, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>
{
    int32_t WINRT_CALL GetFlyoutPlacementTargetInfo(void* placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* targetPreferredPlacement, bool* allowFallbacks, Windows::Foundation::Rect* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlyoutPlacementTargetInfo, WINRT_WRAP(Windows::Foundation::Rect), Windows::UI::Xaml::FrameworkElement const&, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const&, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode&, bool&);
            *returnValue = detach_from<Windows::Foundation::Rect>(this->shim().GetFlyoutPlacementTargetInfo(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&placementTarget), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&preferredPlacement), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode*>(targetPreferredPlacement), *allowFallbacks));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlyoutPlacement(Windows::Foundation::Rect placementTargetBounds, Windows::Foundation::Size controlSize, Windows::Foundation::Size minControlSize, Windows::Foundation::Rect containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode* chosenPlacement, Windows::Foundation::Rect* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlyoutPlacement, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&, Windows::Foundation::Size const&, Windows::Foundation::Size const&, Windows::Foundation::Rect const&, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const&, bool, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode&);
            *returnValue = detach_from<Windows::Foundation::Rect>(this->shim().GetFlyoutPlacement(*reinterpret_cast<Windows::Foundation::Rect const*>(&placementTargetBounds), *reinterpret_cast<Windows::Foundation::Size const*>(&controlSize), *reinterpret_cast<Windows::Foundation::Size const*>(&minControlSize), *reinterpret_cast<Windows::Foundation::Rect const*>(&containerRect), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const*>(&targetPreferredPlacement), allowFallbacks, *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode*>(chosenPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Hosting {

inline DesignerAppManager::DesignerAppManager(param::hstring const& appUserModelId) :
    DesignerAppManager(impl::call_factory<DesignerAppManager, Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory>([&](auto&& f) { return f.Create(appUserModelId); }))
{}

inline DesktopWindowXamlSource::DesktopWindowXamlSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Composition::Visual ElementCompositionPreview::GetElementVisual(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>([&](auto&& f) { return f.GetElementVisual(element); });
}

inline Windows::UI::Composition::Visual ElementCompositionPreview::GetElementChildVisual(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>([&](auto&& f) { return f.GetElementChildVisual(element); });
}

inline void ElementCompositionPreview::SetElementChildVisual(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::Visual const& visual)
{
    impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>([&](auto&& f) { return f.SetElementChildVisual(element, visual); });
}

inline Windows::UI::Composition::CompositionPropertySet ElementCompositionPreview::GetScrollViewerManipulationPropertySet(Windows::UI::Xaml::Controls::ScrollViewer const& scrollViewer)
{
    return impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics>([&](auto&& f) { return f.GetScrollViewerManipulationPropertySet(scrollViewer); });
}

inline void ElementCompositionPreview::SetImplicitShowAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation)
{
    impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>([&](auto&& f) { return f.SetImplicitShowAnimation(element, animation); });
}

inline void ElementCompositionPreview::SetImplicitHideAnimation(Windows::UI::Xaml::UIElement const& element, Windows::UI::Composition::ICompositionAnimationBase const& animation)
{
    impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>([&](auto&& f) { return f.SetImplicitHideAnimation(element, animation); });
}

inline void ElementCompositionPreview::SetIsTranslationEnabled(Windows::UI::Xaml::UIElement const& element, bool value)
{
    impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>([&](auto&& f) { return f.SetIsTranslationEnabled(element, value); });
}

inline Windows::UI::Composition::CompositionPropertySet ElementCompositionPreview::GetPointerPositionPropertySet(Windows::UI::Xaml::UIElement const& targetElement)
{
    return impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2>([&](auto&& f) { return f.GetPointerPositionPropertySet(targetElement); });
}

inline void ElementCompositionPreview::SetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow, Windows::UI::Xaml::UIElement const& xamlContent)
{
    impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>([&](auto&& f) { return f.SetAppWindowContent(appWindow, xamlContent); });
}

inline Windows::UI::Xaml::UIElement ElementCompositionPreview::GetAppWindowContent(Windows::UI::WindowManagement::AppWindow const& appWindow)
{
    return impl::call_factory<ElementCompositionPreview, Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3>([&](auto&& f) { return f.GetAppWindowContent(appWindow); });
}

inline Windows::UI::Xaml::Hosting::WindowsXamlManager WindowsXamlManager::InitializeForCurrentThread()
{
    return impl::call_factory<WindowsXamlManager, Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics>([&](auto&& f) { return f.InitializeForCurrentThread(); });
}

inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason) :
    XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>([&](auto&& f) { return f.CreateInstance(reason); }))
{}

inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect) :
    XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>([&](auto&& f) { return f.CreateInstanceWithHintRect(reason, hintRect); }))
{}

inline XamlSourceFocusNavigationRequest::XamlSourceFocusNavigationRequest(Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationReason const& reason, Windows::Foundation::Rect const& hintRect, winrt::guid const& correlationId) :
    XamlSourceFocusNavigationRequest(impl::call_factory<XamlSourceFocusNavigationRequest, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory>([&](auto&& f) { return f.CreateInstanceWithHintRectAndCorrelationId(reason, hintRect, correlationId); }))
{}

inline XamlSourceFocusNavigationResult::XamlSourceFocusNavigationResult(bool focusMoved) :
    XamlSourceFocusNavigationResult(impl::call_factory<XamlSourceFocusNavigationResult, Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory>([&](auto&& f) { return f.CreateInstance(focusMoved); }))
{}

inline bool XamlUIPresenter::CompleteTimelinesAutomatically()
{
    return impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>([&](auto&& f) { return f.CompleteTimelinesAutomatically(); });
}

inline void XamlUIPresenter::CompleteTimelinesAutomatically(bool value)
{
    impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>([&](auto&& f) { return f.CompleteTimelinesAutomatically(value); });
}

inline void XamlUIPresenter::SetHost(Windows::UI::Xaml::Hosting::IXamlUIPresenterHost const& host)
{
    impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>([&](auto&& f) { return f.SetHost(host); });
}

inline void XamlUIPresenter::NotifyWindowSizeChanged()
{
    impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics>([&](auto&& f) { return f.NotifyWindowSizeChanged(); });
}

inline Windows::Foundation::Rect XamlUIPresenter::GetFlyoutPlacementTargetInfo(Windows::UI::Xaml::FrameworkElement const& placementTarget, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& preferredPlacement, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& targetPreferredPlacement, bool& allowFallbacks)
{
    return impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>([&](auto&& f) { return f.GetFlyoutPlacementTargetInfo(placementTarget, preferredPlacement, targetPreferredPlacement, allowFallbacks); });
}

inline Windows::Foundation::Rect XamlUIPresenter::GetFlyoutPlacement(Windows::Foundation::Rect const& placementTargetBounds, Windows::Foundation::Size const& controlSize, Windows::Foundation::Size const& minControlSize, Windows::Foundation::Rect const& containerRect, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode const& targetPreferredPlacement, bool allowFallbacks, Windows::UI::Xaml::Controls::Primitives::FlyoutPlacementMode& chosenPlacement)
{
    return impl::call_factory<XamlUIPresenter, Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2>([&](auto&& f) { return f.GetFlyoutPlacement(placementTargetBounds, controlSize, minControlSize, containerRect, targetPreferredPlacement, allowFallbacks, chosenPlacement); });
}

template <typename D, typename... Interfaces>
struct DesktopWindowXamlSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource, Windows::Foundation::IClosable>,
    impl::base<D, Windows::UI::Xaml::Hosting::DesktopWindowXamlSource>
{
    using composable = DesktopWindowXamlSource;

protected:
    DesktopWindowXamlSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Hosting::DesktopWindowXamlSource, Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesignerAppExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesignerAppManagerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesignerAppView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesignerAppView> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceGotFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IDesktopWindowXamlSourceTakeFocusRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreview> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreview> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IElementCompositionPreviewStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IWindowsXamlManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationRequestFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResult> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlSourceFocusNavigationResultFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterHost3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::IXamlUIPresenterStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesignerAppExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesignerAppManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesignerAppView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesignerAppView> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceGotFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::DesktopWindowXamlSourceTakeFocusRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::ElementCompositionPreview> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::ElementCompositionPreview> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::WindowsXamlManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::XamlSourceFocusNavigationResult> {};
template<> struct hash<winrt::Windows::UI::Xaml::Hosting::XamlUIPresenter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Hosting::XamlUIPresenter> {};

}
