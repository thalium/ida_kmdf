// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrast() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IAccessibilitySettings)->get_HighContrast(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrastScheme() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IAccessibilitySettings)->get_HighContrastScheme(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrastChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IAccessibilitySettings)->add_HighContrastChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrastChanged_revoker consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrastChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, HighContrastChanged_revoker>(this, HighContrastChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>::HighContrastChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IAccessibilitySettings)->remove_HighContrastChanged(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IActivationViewSwitcher<D>::ShowAsStandaloneAsync(int32_t viewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IActivationViewSwitcher)->ShowAsStandaloneAsync(viewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IActivationViewSwitcher<D>::ShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IActivationViewSwitcher)->ShowAsStandaloneWithSizePreferenceAsync(viewId, get_abi(sizePreference), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IActivationViewSwitcher<D>::IsViewPresentedOnActivationVirtualDesktop(int32_t viewId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IActivationViewSwitcher)->IsViewPresentedOnActivationVirtualDesktop(viewId, &value));
    return value;
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewOrientation consume_Windows_UI_ViewManagement_IApplicationView<D>::Orientation() const
{
    Windows::UI::ViewManagement::ApplicationViewOrientation value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView<D>::AdjacentToLeftDisplayEdge() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_AdjacentToLeftDisplayEdge(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView<D>::AdjacentToRightDisplayEdge() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_AdjacentToRightDisplayEdge(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView<D>::IsFullScreen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_IsFullScreen(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView<D>::IsOnLockScreen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_IsOnLockScreen(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView<D>::IsScreenCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_IsScreenCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView<D>::IsScreenCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->put_IsScreenCaptureEnabled(value));
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IApplicationView<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_Title(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_ViewManagement_IApplicationView<D>::Id() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->get_Id(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IApplicationView<D>::Consolidated(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->add_Consolidated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IApplicationView<D>::Consolidated_revoker consume_Windows_UI_ViewManagement_IApplicationView<D>::Consolidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Consolidated_revoker>(this, Consolidated(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView<D>::Consolidated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView)->remove_Consolidated(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView2<D>::SuppressSystemOverlays() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->get_SuppressSystemOverlays(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView2<D>::SuppressSystemOverlays(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->put_SuppressSystemOverlays(value));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_IApplicationView2<D>::VisibleBounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->get_VisibleBounds(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IApplicationView2<D>::VisibleBoundsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->add_VisibleBoundsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IApplicationView2<D>::VisibleBoundsChanged_revoker consume_Windows_UI_ViewManagement_IApplicationView2<D>::VisibleBoundsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, VisibleBoundsChanged_revoker>(this, VisibleBoundsChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView2<D>::VisibleBoundsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->remove_VisibleBoundsChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView2<D>::SetDesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode const& boundsMode) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->SetDesiredBoundsMode(get_abi(boundsMode), &success));
    return success;
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewBoundsMode consume_Windows_UI_ViewManagement_IApplicationView2<D>::DesiredBoundsMode() const
{
    Windows::UI::ViewManagement::ApplicationViewBoundsMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView2)->get_DesiredBoundsMode(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewTitleBar consume_Windows_UI_ViewManagement_IApplicationView3<D>::TitleBar() const
{
    Windows::UI::ViewManagement::ApplicationViewTitleBar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->get_TitleBar(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::FullScreenSystemOverlayMode consume_Windows_UI_ViewManagement_IApplicationView3<D>::FullScreenSystemOverlayMode() const
{
    Windows::UI::ViewManagement::FullScreenSystemOverlayMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->get_FullScreenSystemOverlayMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView3<D>::FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->put_FullScreenSystemOverlayMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView3<D>::IsFullScreenMode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->get_IsFullScreenMode(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView3<D>::TryEnterFullScreenMode() const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->TryEnterFullScreenMode(&success));
    return success;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView3<D>::ExitFullScreenMode() const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->ExitFullScreenMode());
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView3<D>::ShowStandardSystemOverlays() const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->ShowStandardSystemOverlays());
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView3<D>::TryResizeView(Windows::Foundation::Size const& value) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->TryResizeView(get_abi(value), &success));
    return success;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView3<D>::SetPreferredMinSize(Windows::Foundation::Size const& minSize) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView3)->SetPreferredMinSize(get_abi(minSize)));
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewMode consume_Windows_UI_ViewManagement_IApplicationView4<D>::ViewMode() const
{
    Windows::UI::ViewManagement::ApplicationViewMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView4)->get_ViewMode(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationView4<D>::IsViewModeSupported(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const
{
    bool isViewModeSupported{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView4)->IsViewModeSupported(get_abi(viewMode), &isViewModeSupported));
    return isViewModeSupported;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationView4<D>::TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView4)->TryEnterViewModeAsync(get_abi(viewMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationView4<D>::TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView4)->TryEnterViewModeWithPreferencesAsync(get_abi(viewMode), get_abi(viewModePreferences), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationView4<D>::TryConsolidateAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView4)->TryConsolidateAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IApplicationView7<D>::PersistedStateId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView7)->get_PersistedStateId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationView7<D>::PersistedStateId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView7)->put_PersistedStateId(get_abi(value)));
}

template <typename D> Windows::UI::WindowManagement::WindowingEnvironment consume_Windows_UI_ViewManagement_IApplicationView9<D>::WindowingEnvironment() const
{
    Windows::UI::WindowManagement::WindowingEnvironment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView9)->get_WindowingEnvironment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> consume_Windows_UI_ViewManagement_IApplicationView9<D>::GetDisplayRegions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::WindowManagement::DisplayRegion> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationView9)->GetDisplayRegions(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs<D>::IsUserInitiated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs)->get_IsUserInitiated(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs2<D>::IsAppInitiated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2)->get_IsAppInitiated(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewFullscreenStatics<D>::TryUnsnapToFullscreen() const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewFullscreenStatics)->TryUnsnapToFullscreen(&success));
    return success;
}

template <typename D> int32_t consume_Windows_UI_ViewManagement_IApplicationViewInteropStatics<D>::GetApplicationViewIdForWindow(Windows::UI::Core::ICoreWindow const& window) const
{
    int32_t id{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewInteropStatics)->GetApplicationViewIdForWindow(get_abi(window), &id));
    return id;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics<D>::DisableLayoutScaling() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewScalingStatics)->get_DisableLayoutScaling(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics<D>::TrySetDisableLayoutScaling(bool disableLayoutScaling) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewScalingStatics)->TrySetDisableLayoutScaling(disableLayoutScaling, &success));
    return success;
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewState consume_Windows_UI_ViewManagement_IApplicationViewStatics<D>::Value() const
{
    Windows::UI::ViewManagement::ApplicationViewState value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics)->get_Value(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewStatics<D>::TryUnsnap() const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics)->TryUnsnap(&success));
    return success;
}

template <typename D> Windows::UI::ViewManagement::ApplicationView consume_Windows_UI_ViewManagement_IApplicationViewStatics2<D>::GetForCurrentView() const
{
    Windows::UI::ViewManagement::ApplicationView current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics2)->GetForCurrentView(put_abi(current)));
    return current;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IApplicationViewStatics2<D>::TerminateAppOnFinalViewClose() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics2)->get_TerminateAppOnFinalViewClose(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewStatics2<D>::TerminateAppOnFinalViewClose(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics2)->put_TerminateAppOnFinalViewClose(value));
}

template <typename D> Windows::UI::ViewManagement::ApplicationViewWindowingMode consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>::PreferredLaunchWindowingMode() const
{
    Windows::UI::ViewManagement::ApplicationViewWindowingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics3)->get_PreferredLaunchWindowingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>::PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics3)->put_PreferredLaunchWindowingMode(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>::PreferredLaunchViewSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics3)->get_PreferredLaunchViewSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>::PreferredLaunchViewSize(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics3)->put_PreferredLaunchViewSize(get_abi(value)));
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewStatics4<D>::ClearAllPersistedState() const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics4)->ClearAllPersistedState());
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewStatics4<D>::ClearPersistedState(param::hstring const& key) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewStatics4)->ClearPersistedState(get_abi(key)));
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::DisableShowingMainViewOnActivation() const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->DisableShowingMainViewOnActivation());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::TryShowAsStandaloneAsync(int32_t viewId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->TryShowAsStandaloneAsync(viewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->TryShowAsStandaloneWithSizePreferenceAsync(viewId, get_abi(sizePreference), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference, int32_t anchorViewId, Windows::UI::ViewManagement::ViewSizePreference const& anchorSizePreference) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->TryShowAsStandaloneWithAnchorViewAndSizePreferenceAsync(viewId, get_abi(sizePreference), anchorViewId, get_abi(anchorSizePreference), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::SwitchAsync(int32_t viewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->SwitchAsync(viewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::SwitchAsync(int32_t toViewId, int32_t fromViewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->SwitchFromViewAsync(toViewId, fromViewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::SwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->SwitchFromViewWithOptionsAsync(toViewId, fromViewId, get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>::PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics)->PrepareForCustomAnimatedSwitchAsync(toViewId, fromViewId, get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics2<D>::DisableSystemViewActivationPolicy() const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2)->DisableSystemViewActivationPolicy());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3<D>::TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3)->TryShowAsViewModeAsync(viewId, get_abi(viewMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3<D>::TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3)->TryShowAsViewModeWithPreferencesAsync(viewId, get_abi(viewMode), get_abi(viewModePreferences), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::BackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::BackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonHoverForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonHoverForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonHoverForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonHoverForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonHoverBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonHoverBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonHoverBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonHoverBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonPressedForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonPressedForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonPressedForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonPressedForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonPressedBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonPressedBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonPressedBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonPressedBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::InactiveForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_InactiveForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::InactiveForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_InactiveForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::InactiveBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_InactiveBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::InactiveBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_InactiveBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonInactiveForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonInactiveForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonInactiveForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonInactiveForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonInactiveBackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->put_ButtonInactiveBackgroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>::ButtonInactiveBackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTitleBar)->get_ButtonInactiveBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_ViewManagement_IApplicationViewTransferContext<D>::ViewId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTransferContext)->get_ViewId(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IApplicationViewTransferContext<D>::ViewId(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTransferContext)->put_ViewId(value));
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IApplicationViewTransferContextStatics<D>::DataPackageFormatId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewTransferContextStatics)->get_DataPackageFormatId(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_ViewManagement_IApplicationViewWithContext<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IApplicationViewWithContext)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IInputPane<D>::Showing(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPane)->add_Showing(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IInputPane<D>::Showing_revoker consume_Windows_UI_ViewManagement_IInputPane<D>::Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Showing_revoker>(this, Showing(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IInputPane<D>::Showing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IInputPane)->remove_Showing(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IInputPane<D>::Hiding(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPane)->add_Hiding(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IInputPane<D>::Hiding_revoker consume_Windows_UI_ViewManagement_IInputPane<D>::Hiding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Hiding_revoker>(this, Hiding(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IInputPane<D>::Hiding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IInputPane)->remove_Hiding(get_abi(token)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_IInputPane<D>::OccludedRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPane)->get_OccludedRect(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IInputPane2<D>::TryShow() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPane2)->TryShow(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IInputPane2<D>::TryHide() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPane2)->TryHide(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IInputPaneControl<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneControl)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IInputPaneControl<D>::Visible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneControl)->put_Visible(value));
}

template <typename D> Windows::UI::ViewManagement::InputPane consume_Windows_UI_ViewManagement_IInputPaneStatics<D>::GetForCurrentView() const
{
    Windows::UI::ViewManagement::InputPane inputPane{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneStatics)->GetForCurrentView(put_abi(inputPane)));
    return inputPane;
}

template <typename D> Windows::UI::ViewManagement::InputPane consume_Windows_UI_ViewManagement_IInputPaneStatics2<D>::GetForUIContext(Windows::UI::UIContext const& context) const
{
    Windows::UI::ViewManagement::InputPane result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneStatics2)->GetForUIContext(get_abi(context), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs<D>::OccludedRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs)->get_OccludedRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs<D>::EnsuredFocusedElementInView(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs)->put_EnsuredFocusedElementInView(value));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs<D>::EnsuredFocusedElementInView() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs)->get_EnsuredFocusedElementInView(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->StartProjectingAsync(projectionViewId, anchorViewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->SwapDisplaysForViewsAsync(projectionViewId, anchorViewId, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->StopProjectingAsync(projectionViewId, anchorViewId, put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::ProjectionDisplayAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->get_ProjectionDisplayAvailable(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::ProjectionDisplayAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->add_ProjectionDisplayAvailableChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::ProjectionDisplayAvailableChanged_revoker consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::ProjectionDisplayAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ProjectionDisplayAvailableChanged_revoker>(this, ProjectionDisplayAvailableChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>::ProjectionDisplayAvailableChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics)->remove_ProjectionDisplayAvailableChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>::StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Devices::Enumeration::DeviceInformation const& displayDeviceInfo) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics2)->StartProjectingWithDeviceInfoAsync(projectionViewId, anchorViewId, get_abi(displayDeviceInfo), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>::RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics2)->RequestStartProjectingAsync(projectionViewId, anchorViewId, get_abi(selection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>::RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& prefferedPlacement) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics2)->RequestStartProjectingWithPlacementAsync(projectionViewId, anchorViewId, get_abi(selection), get_abi(prefferedPlacement), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>::GetDeviceSelector() const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IProjectionManagerStatics2)->GetDeviceSelector(put_abi(selector)));
    return selector;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IStatusBar<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->ShowAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IStatusBar<D>::HideAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->HideAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> double consume_Windows_UI_ViewManagement_IStatusBar<D>::BackgroundOpacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->get_BackgroundOpacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBar<D>::BackgroundOpacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->put_BackgroundOpacity(value));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IStatusBar<D>::ForegroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBar<D>::ForegroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_ViewManagement_IStatusBar<D>::BackgroundColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBar<D>::BackgroundColor(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::ViewManagement::StatusBarProgressIndicator consume_Windows_UI_ViewManagement_IStatusBar<D>::ProgressIndicator() const
{
    Windows::UI::ViewManagement::StatusBarProgressIndicator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->get_ProgressIndicator(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_IStatusBar<D>::OccludedRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->get_OccludedRect(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IStatusBar<D>::Showing(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->add_Showing(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IStatusBar<D>::Showing_revoker consume_Windows_UI_ViewManagement_IStatusBar<D>::Showing(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, Showing_revoker>(this, Showing(eventHandler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBar<D>::Showing(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->remove_Showing(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IStatusBar<D>::Hiding(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->add_Hiding(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IStatusBar<D>::Hiding_revoker consume_Windows_UI_ViewManagement_IStatusBar<D>::Hiding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, Hiding_revoker>(this, Hiding(eventHandler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBar<D>::Hiding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IStatusBar)->remove_Hiding(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::ShowAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->ShowAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::HideAsync() const
{
    Windows::Foundation::IAsyncAction returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->HideAsync(put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->put_Text(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::ProgressValue() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->get_ProgressValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>::ProgressValue(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarProgressIndicator)->put_ProgressValue(get_abi(value)));
}

template <typename D> Windows::UI::ViewManagement::StatusBar consume_Windows_UI_ViewManagement_IStatusBarStatics<D>::GetForCurrentView() const
{
    Windows::UI::ViewManagement::StatusBar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IStatusBarStatics)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::HandPreference consume_Windows_UI_ViewManagement_IUISettings<D>::HandPreference() const
{
    Windows::UI::ViewManagement::HandPreference value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_HandPreference(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IUISettings<D>::CursorSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_CursorSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IUISettings<D>::ScrollBarSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_ScrollBarSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IUISettings<D>::ScrollBarArrowSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_ScrollBarArrowSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IUISettings<D>::ScrollBarThumbBoxSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_ScrollBarThumbBoxSize(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_ViewManagement_IUISettings<D>::MessageDuration() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_MessageDuration(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IUISettings<D>::AnimationsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_AnimationsEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_IUISettings<D>::CaretBrowsingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_CaretBrowsingEnabled(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_ViewManagement_IUISettings<D>::CaretBlinkRate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_CaretBlinkRate(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_ViewManagement_IUISettings<D>::CaretWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_CaretWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_ViewManagement_IUISettings<D>::DoubleClickTime() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_DoubleClickTime(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_ViewManagement_IUISettings<D>::MouseHoverTime() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->get_MouseHoverTime(&value));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_ViewManagement_IUISettings<D>::UIElementColor(Windows::UI::ViewManagement::UIElementType const& desiredElement) const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings)->UIElementColor(get_abi(desiredElement), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_ViewManagement_IUISettings2<D>::TextScaleFactor() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings2)->get_TextScaleFactor(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IUISettings2<D>::TextScaleFactorChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings2)->add_TextScaleFactorChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IUISettings2<D>::TextScaleFactorChanged_revoker consume_Windows_UI_ViewManagement_IUISettings2<D>::TextScaleFactorChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, TextScaleFactorChanged_revoker>(this, TextScaleFactorChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IUISettings2<D>::TextScaleFactorChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IUISettings2)->remove_TextScaleFactorChanged(get_abi(cookie)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_ViewManagement_IUISettings3<D>::GetColorValue(Windows::UI::ViewManagement::UIColorType const& desiredColor) const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings3)->GetColorValue(get_abi(desiredColor), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IUISettings3<D>::ColorValuesChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings3)->add_ColorValuesChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IUISettings3<D>::ColorValuesChanged_revoker consume_Windows_UI_ViewManagement_IUISettings3<D>::ColorValuesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ColorValuesChanged_revoker>(this, ColorValuesChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IUISettings3<D>::ColorValuesChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IUISettings3)->remove_ColorValuesChanged(get_abi(cookie)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IUISettings4<D>::AdvancedEffectsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings4)->get_AdvancedEffectsEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IUISettings4<D>::AdvancedEffectsEnabledChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings4)->add_AdvancedEffectsEnabledChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IUISettings4<D>::AdvancedEffectsEnabledChanged_revoker consume_Windows_UI_ViewManagement_IUISettings4<D>::AdvancedEffectsEnabledChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AdvancedEffectsEnabledChanged_revoker>(this, AdvancedEffectsEnabledChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IUISettings4<D>::AdvancedEffectsEnabledChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IUISettings4)->remove_AdvancedEffectsEnabledChanged(get_abi(cookie)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_IUISettings5<D>::AutoHideScrollBars() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings5)->get_AutoHideScrollBars(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_IUISettings5<D>::AutoHideScrollBarsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUISettings5)->add_AutoHideScrollBarsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_IUISettings5<D>::AutoHideScrollBarsChanged_revoker consume_Windows_UI_ViewManagement_IUISettings5<D>::AutoHideScrollBarsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AutoHideScrollBarsChanged_revoker>(this, AutoHideScrollBarsChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_IUISettings5<D>::AutoHideScrollBarsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::IUISettings5)->remove_AutoHideScrollBarsChanged(get_abi(token)));
}

template <typename D> Windows::UI::ViewManagement::UserInteractionMode consume_Windows_UI_ViewManagement_IUIViewSettings<D>::UserInteractionMode() const
{
    Windows::UI::ViewManagement::UserInteractionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUIViewSettings)->get_UserInteractionMode(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::UIViewSettings consume_Windows_UI_ViewManagement_IUIViewSettingsStatics<D>::GetForCurrentView() const
{
    Windows::UI::ViewManagement::UIViewSettings current{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IUIViewSettingsStatics)->GetForCurrentView(put_abi(current)));
    return current;
}

template <typename D> Windows::UI::ViewManagement::ViewSizePreference consume_Windows_UI_ViewManagement_IViewModePreferences<D>::ViewSizePreference() const
{
    Windows::UI::ViewManagement::ViewSizePreference value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IViewModePreferences)->get_ViewSizePreference(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IViewModePreferences<D>::ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IViewModePreferences)->put_ViewSizePreference(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_ViewManagement_IViewModePreferences<D>::CustomSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IViewModePreferences)->get_CustomSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_IViewModePreferences<D>::CustomSize(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IViewModePreferences)->put_CustomSize(get_abi(value)));
}

template <typename D> Windows::UI::ViewManagement::ViewModePreferences consume_Windows_UI_ViewManagement_IViewModePreferencesStatics<D>::CreateDefault(Windows::UI::ViewManagement::ApplicationViewMode const& mode) const
{
    Windows::UI::ViewManagement::ViewModePreferences result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::IViewModePreferencesStatics)->CreateDefault(get_abi(mode), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IAccessibilitySettings> : produce_base<D, Windows::UI::ViewManagement::IAccessibilitySettings>
{
    int32_t WINRT_CALL get_HighContrast(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrast, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HighContrast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HighContrastScheme(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastScheme, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HighContrastScheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HighContrastChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().HighContrastChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::AccessibilitySettings, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HighContrastChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HighContrastChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HighContrastChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IActivationViewSwitcher> : produce_base<D, Windows::UI::ViewManagement::IActivationViewSwitcher>
{
    int32_t WINRT_CALL ShowAsStandaloneAsync(int32_t viewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsStandaloneAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsStandaloneAsync(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAsStandaloneWithSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsStandaloneAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, Windows::UI::ViewManagement::ViewSizePreference const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsStandaloneAsync(viewId, *reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&sizePreference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsViewPresentedOnActivationVirtualDesktop(int32_t viewId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsViewPresentedOnActivationVirtualDesktop, WINRT_WRAP(bool), int32_t);
            *value = detach_from<bool>(this->shim().IsViewPresentedOnActivationVirtualDesktop(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView> : produce_base<D, Windows::UI::ViewManagement::IApplicationView>
{
    int32_t WINRT_CALL get_Orientation(Windows::UI::ViewManagement::ApplicationViewOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewOrientation));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewOrientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdjacentToLeftDisplayEdge(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdjacentToLeftDisplayEdge, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AdjacentToLeftDisplayEdge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdjacentToRightDisplayEdge(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdjacentToRightDisplayEdge, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AdjacentToRightDisplayEdge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFullScreen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFullScreen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFullScreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnLockScreen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnLockScreen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnLockScreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsScreenCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScreenCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScreenCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsScreenCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScreenCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsScreenCaptureEnabled(value);
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

    int32_t WINRT_CALL get_Id(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Consolidated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Consolidated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Consolidated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Consolidated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Consolidated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Consolidated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView2> : produce_base<D, Windows::UI::ViewManagement::IApplicationView2>
{
    int32_t WINRT_CALL get_SuppressSystemOverlays(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressSystemOverlays, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SuppressSystemOverlays());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuppressSystemOverlays(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressSystemOverlays, WINRT_WRAP(void), bool);
            this->shim().SuppressSystemOverlays(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibleBounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleBounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().VisibleBounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_VisibleBoundsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleBoundsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VisibleBoundsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::ApplicationView, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisibleBoundsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisibleBoundsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisibleBoundsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SetDesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode boundsMode, bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDesiredBoundsMode, WINRT_WRAP(bool), Windows::UI::ViewManagement::ApplicationViewBoundsMode const&);
            *success = detach_from<bool>(this->shim().SetDesiredBoundsMode(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewBoundsMode const*>(&boundsMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredBoundsMode(Windows::UI::ViewManagement::ApplicationViewBoundsMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredBoundsMode, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewBoundsMode));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewBoundsMode>(this->shim().DesiredBoundsMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView3> : produce_base<D, Windows::UI::ViewManagement::IApplicationView3>
{
    int32_t WINRT_CALL get_TitleBar(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleBar, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewTitleBar));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewTitleBar>(this->shim().TitleBar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullScreenSystemOverlayMode, WINRT_WRAP(Windows::UI::ViewManagement::FullScreenSystemOverlayMode));
            *value = detach_from<Windows::UI::ViewManagement::FullScreenSystemOverlayMode>(this->shim().FullScreenSystemOverlayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FullScreenSystemOverlayMode(Windows::UI::ViewManagement::FullScreenSystemOverlayMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullScreenSystemOverlayMode, WINRT_WRAP(void), Windows::UI::ViewManagement::FullScreenSystemOverlayMode const&);
            this->shim().FullScreenSystemOverlayMode(*reinterpret_cast<Windows::UI::ViewManagement::FullScreenSystemOverlayMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFullScreenMode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFullScreenMode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFullScreenMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnterFullScreenMode(bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnterFullScreenMode, WINRT_WRAP(bool));
            *success = detach_from<bool>(this->shim().TryEnterFullScreenMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExitFullScreenMode() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitFullScreenMode, WINRT_WRAP(void));
            this->shim().ExitFullScreenMode();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowStandardSystemOverlays() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowStandardSystemOverlays, WINRT_WRAP(void));
            this->shim().ShowStandardSystemOverlays();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryResizeView(Windows::Foundation::Size value, bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryResizeView, WINRT_WRAP(bool), Windows::Foundation::Size const&);
            *success = detach_from<bool>(this->shim().TryResizeView(*reinterpret_cast<Windows::Foundation::Size const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreferredMinSize(Windows::Foundation::Size minSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreferredMinSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().SetPreferredMinSize(*reinterpret_cast<Windows::Foundation::Size const*>(&minSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView4> : produce_base<D, Windows::UI::ViewManagement::IApplicationView4>
{
    int32_t WINRT_CALL get_ViewMode(Windows::UI::ViewManagement::ApplicationViewMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewMode, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewMode));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewMode>(this->shim().ViewMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsViewModeSupported(Windows::UI::ViewManagement::ApplicationViewMode viewMode, bool* isViewModeSupported) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsViewModeSupported, WINRT_WRAP(bool), Windows::UI::ViewManagement::ApplicationViewMode const&);
            *isViewModeSupported = detach_from<bool>(this->shim().IsViewModeSupported(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&viewMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnterViewModeAsync(Windows::UI::ViewManagement::ApplicationViewMode viewMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnterViewModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::ViewManagement::ApplicationViewMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryEnterViewModeAsync(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&viewMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnterViewModeWithPreferencesAsync(Windows::UI::ViewManagement::ApplicationViewMode viewMode, void* viewModePreferences, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnterViewModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::ViewManagement::ApplicationViewMode const, Windows::UI::ViewManagement::ViewModePreferences const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryEnterViewModeAsync(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&viewMode), *reinterpret_cast<Windows::UI::ViewManagement::ViewModePreferences const*>(&viewModePreferences)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryConsolidateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryConsolidateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryConsolidateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView7> : produce_base<D, Windows::UI::ViewManagement::IApplicationView7>
{
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
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationView9> : produce_base<D, Windows::UI::ViewManagement::IApplicationView9>
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
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>
{
    int32_t WINRT_CALL get_IsUserInitiated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserInitiated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUserInitiated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>
{
    int32_t WINRT_CALL get_IsAppInitiated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppInitiated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppInitiated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewFullscreenStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>
{
    int32_t WINRT_CALL TryUnsnapToFullscreen(bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUnsnapToFullscreen, WINRT_WRAP(bool));
            *success = detach_from<bool>(this->shim().TryUnsnapToFullscreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewInteropStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewInteropStatics>
{
    int32_t WINRT_CALL GetApplicationViewIdForWindow(void* window, int32_t* id) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetApplicationViewIdForWindow, WINRT_WRAP(int32_t), Windows::UI::Core::ICoreWindow const&);
            *id = detach_from<int32_t>(this->shim().GetApplicationViewIdForWindow(*reinterpret_cast<Windows::UI::Core::ICoreWindow const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewScaling> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewScaling>
{};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewScalingStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewScalingStatics>
{
    int32_t WINRT_CALL get_DisableLayoutScaling(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableLayoutScaling, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DisableLayoutScaling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetDisableLayoutScaling(bool disableLayoutScaling, bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetDisableLayoutScaling, WINRT_WRAP(bool), bool);
            *success = detach_from<bool>(this->shim().TrySetDisableLayoutScaling(disableLayoutScaling));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewStatics>
{
    int32_t WINRT_CALL get_Value(Windows::UI::ViewManagement::ApplicationViewState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewState));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewState>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUnsnap(bool* success) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUnsnap, WINRT_WRAP(bool));
            *success = detach_from<bool>(this->shim().TryUnsnap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewStatics2> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewStatics2>
{
    int32_t WINRT_CALL GetForCurrentView(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationView));
            *current = detach_from<Windows::UI::ViewManagement::ApplicationView>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TerminateAppOnFinalViewClose(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminateAppOnFinalViewClose, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TerminateAppOnFinalViewClose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TerminateAppOnFinalViewClose(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminateAppOnFinalViewClose, WINRT_WRAP(void), bool);
            this->shim().TerminateAppOnFinalViewClose(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewStatics3> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewStatics3>
{
    int32_t WINRT_CALL get_PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredLaunchWindowingMode, WINRT_WRAP(Windows::UI::ViewManagement::ApplicationViewWindowingMode));
            *value = detach_from<Windows::UI::ViewManagement::ApplicationViewWindowingMode>(this->shim().PreferredLaunchWindowingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredLaunchWindowingMode, WINRT_WRAP(void), Windows::UI::ViewManagement::ApplicationViewWindowingMode const&);
            this->shim().PreferredLaunchWindowingMode(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewWindowingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredLaunchViewSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredLaunchViewSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().PreferredLaunchViewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredLaunchViewSize(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredLaunchViewSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().PreferredLaunchViewSize(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewStatics4> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewStatics4>
{
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
struct produce<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>
{
    int32_t WINRT_CALL DisableShowingMainViewOnActivation() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableShowingMainViewOnActivation, WINRT_WRAP(void));
            this->shim().DisableShowingMainViewOnActivation();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowAsStandaloneAsync(int32_t viewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsStandaloneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsStandaloneAsync(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowAsStandaloneWithSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsStandaloneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, Windows::UI::ViewManagement::ViewSizePreference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsStandaloneAsync(viewId, *reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&sizePreference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowAsStandaloneWithAnchorViewAndSizePreferenceAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference sizePreference, int32_t anchorViewId, Windows::UI::ViewManagement::ViewSizePreference anchorSizePreference, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsStandaloneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, Windows::UI::ViewManagement::ViewSizePreference const, int32_t, Windows::UI::ViewManagement::ViewSizePreference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsStandaloneAsync(viewId, *reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&sizePreference), anchorViewId, *reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&anchorSizePreference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SwitchAsync(int32_t viewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwitchAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SwitchAsync(viewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SwitchFromViewAsync(int32_t toViewId, int32_t fromViewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwitchAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SwitchAsync(toViewId, fromViewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SwitchFromViewWithOptionsAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwitchAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SwitchAsync(toViewId, fromViewId, *reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareForCustomAnimatedSwitchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, int32_t, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().PrepareForCustomAnimatedSwitchAsync(toViewId, fromViewId, *reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>
{
    int32_t WINRT_CALL DisableSystemViewActivationPolicy() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableSystemViewActivationPolicy, WINRT_WRAP(void));
            this->shim().DisableSystemViewActivationPolicy();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>
{
    int32_t WINRT_CALL TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode viewMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsViewModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, Windows::UI::ViewManagement::ApplicationViewMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsViewModeAsync(viewId, *reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&viewMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowAsViewModeWithPreferencesAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode viewMode, void* viewModePreferences, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAsViewModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, Windows::UI::ViewManagement::ApplicationViewMode const, Windows::UI::ViewManagement::ViewModePreferences const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryShowAsViewModeAsync(viewId, *reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&viewMode), *reinterpret_cast<Windows::UI::ViewManagement::ViewModePreferences const*>(&viewModePreferences)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewTitleBar> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewTitleBar>
{
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
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewTransferContext> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewTransferContext>
{
    int32_t WINRT_CALL get_ViewId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ViewId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewId(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewId, WINRT_WRAP(void), int32_t);
            this->shim().ViewId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewTransferContextStatics> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>
{
    int32_t WINRT_CALL get_DataPackageFormatId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataPackageFormatId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DataPackageFormatId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IApplicationViewWithContext> : produce_base<D, Windows::UI::ViewManagement::IApplicationViewWithContext>
{
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
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPane> : produce_base<D, Windows::UI::ViewManagement::IInputPane>
{
    int32_t WINRT_CALL add_Showing(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Showing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Hiding(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hiding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Hiding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::InputPane, Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Hiding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Hiding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Hiding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OccludedRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OccludedRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPane2> : produce_base<D, Windows::UI::ViewManagement::IInputPane2>
{
    int32_t WINRT_CALL TryShow(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShow, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryShow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryHide(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryHide, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryHide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPaneControl> : produce_base<D, Windows::UI::ViewManagement::IInputPaneControl>
{
    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(void), bool);
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPaneStatics> : produce_base<D, Windows::UI::ViewManagement::IInputPaneStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** inputPane) noexcept final
    {
        try
        {
            *inputPane = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::ViewManagement::InputPane));
            *inputPane = detach_from<Windows::UI::ViewManagement::InputPane>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPaneStatics2> : produce_base<D, Windows::UI::ViewManagement::IInputPaneStatics2>
{
    int32_t WINRT_CALL GetForUIContext(void* context, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUIContext, WINRT_WRAP(Windows::UI::ViewManagement::InputPane), Windows::UI::UIContext const&);
            *result = detach_from<Windows::UI::ViewManagement::InputPane>(this->shim().GetForUIContext(*reinterpret_cast<Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs> : produce_base<D, Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>
{
    int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OccludedRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OccludedRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnsuredFocusedElementInView(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnsuredFocusedElementInView, WINRT_WRAP(void), bool);
            this->shim().EnsuredFocusedElementInView(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnsuredFocusedElementInView(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnsuredFocusedElementInView, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnsuredFocusedElementInView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IProjectionManagerStatics> : produce_base<D, Windows::UI::ViewManagement::IProjectionManagerStatics>
{
    int32_t WINRT_CALL StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProjectingAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartProjectingAsync(projectionViewId, anchorViewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwapDisplaysForViewsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SwapDisplaysForViewsAsync(projectionViewId, anchorViewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopProjectingAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopProjectingAsync(projectionViewId, anchorViewId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionDisplayAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionDisplayAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ProjectionDisplayAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ProjectionDisplayAvailableChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionDisplayAvailableChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProjectionDisplayAvailableChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProjectionDisplayAvailableChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProjectionDisplayAvailableChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProjectionDisplayAvailableChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IProjectionManagerStatics2> : produce_base<D, Windows::UI::ViewManagement::IProjectionManagerStatics2>
{
    int32_t WINRT_CALL StartProjectingWithDeviceInfoAsync(int32_t projectionViewId, int32_t anchorViewId, void* displayDeviceInfo, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProjectingAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, int32_t, Windows::Devices::Enumeration::DeviceInformation const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartProjectingAsync(projectionViewId, anchorViewId, *reinterpret_cast<Windows::Devices::Enumeration::DeviceInformation const*>(&displayDeviceInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect selection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStartProjectingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, int32_t, Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestStartProjectingAsync(projectionViewId, anchorViewId, *reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStartProjectingWithPlacementAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect selection, Windows::UI::Popups::Placement prefferedPlacement, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStartProjectingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), int32_t, int32_t, Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestStartProjectingAsync(projectionViewId, anchorViewId, *reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&prefferedPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IStatusBar> : produce_base<D, Windows::UI::ViewManagement::IStatusBar>
{
    int32_t WINRT_CALL ShowAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HideAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HideAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().HideAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundOpacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundOpacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BackgroundOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundOpacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundOpacity, WINRT_WRAP(void), double);
            this->shim().BackgroundOpacity(value);
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

    int32_t WINRT_CALL get_ProgressIndicator(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgressIndicator, WINRT_WRAP(Windows::UI::ViewManagement::StatusBarProgressIndicator));
            *value = detach_from<Windows::UI::ViewManagement::StatusBarProgressIndicator>(this->shim().ProgressIndicator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OccludedRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OccludedRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OccludedRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Showing(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Showing(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Showing(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Showing, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Showing(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Hiding(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hiding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Hiding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::StatusBar, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Hiding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Hiding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Hiding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IStatusBarProgressIndicator> : produce_base<D, Windows::UI::ViewManagement::IStatusBarProgressIndicator>
{
    int32_t WINRT_CALL ShowAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HideAsync(void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HideAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *returnValue = detach_from<Windows::Foundation::IAsyncAction>(this->shim().HideAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProgressValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgressValue, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().ProgressValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProgressValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgressValue, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().ProgressValue(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IStatusBarStatics> : produce_base<D, Windows::UI::ViewManagement::IStatusBarStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::ViewManagement::StatusBar));
            *value = detach_from<Windows::UI::ViewManagement::StatusBar>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettings> : produce_base<D, Windows::UI::ViewManagement::IUISettings>
{
    int32_t WINRT_CALL get_HandPreference(Windows::UI::ViewManagement::HandPreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HandPreference, WINRT_WRAP(Windows::UI::ViewManagement::HandPreference));
            *value = detach_from<Windows::UI::ViewManagement::HandPreference>(this->shim().HandPreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().CursorSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollBarSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollBarSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().ScrollBarSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollBarArrowSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollBarArrowSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().ScrollBarArrowSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScrollBarThumbBoxSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollBarThumbBoxSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().ScrollBarThumbBoxSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageDuration(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageDuration, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MessageDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnimationsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AnimationsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaretBrowsingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaretBrowsingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CaretBrowsingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaretBlinkRate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaretBlinkRate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CaretBlinkRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaretWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaretWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CaretWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DoubleClickTime(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleClickTime, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().DoubleClickTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MouseHoverTime(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseHoverTime, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MouseHoverTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UIElementColor(Windows::UI::ViewManagement::UIElementType desiredElement, struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIElementColor, WINRT_WRAP(Windows::UI::Color), Windows::UI::ViewManagement::UIElementType const&);
            *value = detach_from<Windows::UI::Color>(this->shim().UIElementColor(*reinterpret_cast<Windows::UI::ViewManagement::UIElementType const*>(&desiredElement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettings2> : produce_base<D, Windows::UI::ViewManagement::IUISettings2>
{
    int32_t WINRT_CALL get_TextScaleFactor(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextScaleFactor, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().TextScaleFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TextScaleFactorChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextScaleFactorChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().TextScaleFactorChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TextScaleFactorChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TextScaleFactorChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TextScaleFactorChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettings3> : produce_base<D, Windows::UI::ViewManagement::IUISettings3>
{
    int32_t WINRT_CALL GetColorValue(Windows::UI::ViewManagement::UIColorType desiredColor, struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetColorValue, WINRT_WRAP(Windows::UI::Color), Windows::UI::ViewManagement::UIColorType const&);
            *value = detach_from<Windows::UI::Color>(this->shim().GetColorValue(*reinterpret_cast<Windows::UI::ViewManagement::UIColorType const*>(&desiredColor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ColorValuesChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorValuesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ColorValuesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ColorValuesChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ColorValuesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ColorValuesChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettings4> : produce_base<D, Windows::UI::ViewManagement::IUISettings4>
{
    int32_t WINRT_CALL get_AdvancedEffectsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvancedEffectsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AdvancedEffectsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AdvancedEffectsEnabledChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdvancedEffectsEnabledChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AdvancedEffectsEnabledChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AdvancedEffectsEnabledChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AdvancedEffectsEnabledChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AdvancedEffectsEnabledChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettings5> : produce_base<D, Windows::UI::ViewManagement::IUISettings5>
{
    int32_t WINRT_CALL get_AutoHideScrollBars(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoHideScrollBars, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoHideScrollBars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AutoHideScrollBarsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoHideScrollBarsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AutoHideScrollBarsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::UISettings, Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AutoHideScrollBarsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AutoHideScrollBarsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AutoHideScrollBarsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs> : produce_base<D, Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUIViewSettings> : produce_base<D, Windows::UI::ViewManagement::IUIViewSettings>
{
    int32_t WINRT_CALL get_UserInteractionMode(Windows::UI::ViewManagement::UserInteractionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserInteractionMode, WINRT_WRAP(Windows::UI::ViewManagement::UserInteractionMode));
            *value = detach_from<Windows::UI::ViewManagement::UserInteractionMode>(this->shim().UserInteractionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IUIViewSettingsStatics> : produce_base<D, Windows::UI::ViewManagement::IUIViewSettingsStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** current) noexcept final
    {
        try
        {
            *current = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::ViewManagement::UIViewSettings));
            *current = detach_from<Windows::UI::ViewManagement::UIViewSettings>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IViewModePreferences> : produce_base<D, Windows::UI::ViewManagement::IViewModePreferences>
{
    int32_t WINRT_CALL get_ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewSizePreference, WINRT_WRAP(Windows::UI::ViewManagement::ViewSizePreference));
            *value = detach_from<Windows::UI::ViewManagement::ViewSizePreference>(this->shim().ViewSizePreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewSizePreference(Windows::UI::ViewManagement::ViewSizePreference value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewSizePreference, WINRT_WRAP(void), Windows::UI::ViewManagement::ViewSizePreference const&);
            this->shim().ViewSizePreference(*reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().CustomSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomSize(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomSize, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().CustomSize(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::IViewModePreferencesStatics> : produce_base<D, Windows::UI::ViewManagement::IViewModePreferencesStatics>
{
    int32_t WINRT_CALL CreateDefault(Windows::UI::ViewManagement::ApplicationViewMode mode, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDefault, WINRT_WRAP(Windows::UI::ViewManagement::ViewModePreferences), Windows::UI::ViewManagement::ApplicationViewMode const&);
            *result = detach_from<Windows::UI::ViewManagement::ViewModePreferences>(this->shim().CreateDefault(*reinterpret_cast<Windows::UI::ViewManagement::ApplicationViewMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement {

inline AccessibilitySettings::AccessibilitySettings() :
    AccessibilitySettings(impl::call_factory<AccessibilitySettings>([](auto&& f) { return f.template ActivateInstance<AccessibilitySettings>(); }))
{}

inline bool ApplicationView::TryUnsnapToFullscreen()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>([&](auto&& f) { return f.TryUnsnapToFullscreen(); });
}

inline int32_t ApplicationView::GetApplicationViewIdForWindow(Windows::UI::Core::ICoreWindow const& window)
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewInteropStatics>([&](auto&& f) { return f.GetApplicationViewIdForWindow(window); });
}

inline Windows::UI::ViewManagement::ApplicationViewState ApplicationView::Value()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics>([&](auto&& f) { return f.Value(); });
}

inline bool ApplicationView::TryUnsnap()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics>([&](auto&& f) { return f.TryUnsnap(); });
}

inline Windows::UI::ViewManagement::ApplicationView ApplicationView::GetForCurrentView()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics2>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline bool ApplicationView::TerminateAppOnFinalViewClose()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics2>([&](auto&& f) { return f.TerminateAppOnFinalViewClose(); });
}

inline void ApplicationView::TerminateAppOnFinalViewClose(bool value)
{
    impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics2>([&](auto&& f) { return f.TerminateAppOnFinalViewClose(value); });
}

inline Windows::UI::ViewManagement::ApplicationViewWindowingMode ApplicationView::PreferredLaunchWindowingMode()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics3>([&](auto&& f) { return f.PreferredLaunchWindowingMode(); });
}

inline void ApplicationView::PreferredLaunchWindowingMode(Windows::UI::ViewManagement::ApplicationViewWindowingMode const& value)
{
    impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics3>([&](auto&& f) { return f.PreferredLaunchWindowingMode(value); });
}

inline Windows::Foundation::Size ApplicationView::PreferredLaunchViewSize()
{
    return impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics3>([&](auto&& f) { return f.PreferredLaunchViewSize(); });
}

inline void ApplicationView::PreferredLaunchViewSize(Windows::Foundation::Size const& value)
{
    impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics3>([&](auto&& f) { return f.PreferredLaunchViewSize(value); });
}

inline void ApplicationView::ClearAllPersistedState()
{
    impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics4>([&](auto&& f) { return f.ClearAllPersistedState(); });
}

inline void ApplicationView::ClearPersistedState(param::hstring const& key)
{
    impl::call_factory<ApplicationView, Windows::UI::ViewManagement::IApplicationViewStatics4>([&](auto&& f) { return f.ClearPersistedState(key); });
}

inline bool ApplicationViewScaling::DisableLayoutScaling()
{
    return impl::call_factory<ApplicationViewScaling, Windows::UI::ViewManagement::IApplicationViewScalingStatics>([&](auto&& f) { return f.DisableLayoutScaling(); });
}

inline bool ApplicationViewScaling::TrySetDisableLayoutScaling(bool disableLayoutScaling)
{
    return impl::call_factory<ApplicationViewScaling, Windows::UI::ViewManagement::IApplicationViewScalingStatics>([&](auto&& f) { return f.TrySetDisableLayoutScaling(disableLayoutScaling); });
}

inline void ApplicationViewSwitcher::DisableShowingMainViewOnActivation()
{
    impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.DisableShowingMainViewOnActivation(); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::TryShowAsStandaloneAsync(int32_t viewId)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.TryShowAsStandaloneAsync(viewId); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.TryShowAsStandaloneAsync(viewId, sizePreference); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::TryShowAsStandaloneAsync(int32_t viewId, Windows::UI::ViewManagement::ViewSizePreference const& sizePreference, int32_t anchorViewId, Windows::UI::ViewManagement::ViewSizePreference const& anchorSizePreference)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.TryShowAsStandaloneAsync(viewId, sizePreference, anchorViewId, anchorSizePreference); });
}

inline Windows::Foundation::IAsyncAction ApplicationViewSwitcher::SwitchAsync(int32_t viewId)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.SwitchAsync(viewId); });
}

inline Windows::Foundation::IAsyncAction ApplicationViewSwitcher::SwitchAsync(int32_t toViewId, int32_t fromViewId)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.SwitchAsync(toViewId, fromViewId); });
}

inline Windows::Foundation::IAsyncAction ApplicationViewSwitcher::SwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.SwitchAsync(toViewId, fromViewId, options); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>([&](auto&& f) { return f.PrepareForCustomAnimatedSwitchAsync(toViewId, fromViewId, options); });
}

inline void ApplicationViewSwitcher::DisableSystemViewActivationPolicy()
{
    impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>([&](auto&& f) { return f.DisableSystemViewActivationPolicy(); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>([&](auto&& f) { return f.TryShowAsViewModeAsync(viewId, viewMode); });
}

inline Windows::Foundation::IAsyncOperation<bool> ApplicationViewSwitcher::TryShowAsViewModeAsync(int32_t viewId, Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences)
{
    return impl::call_factory<ApplicationViewSwitcher, Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>([&](auto&& f) { return f.TryShowAsViewModeAsync(viewId, viewMode, viewModePreferences); });
}

inline ApplicationViewTransferContext::ApplicationViewTransferContext() :
    ApplicationViewTransferContext(impl::call_factory<ApplicationViewTransferContext>([](auto&& f) { return f.template ActivateInstance<ApplicationViewTransferContext>(); }))
{}

inline hstring ApplicationViewTransferContext::DataPackageFormatId()
{
    return impl::call_factory<ApplicationViewTransferContext, Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>([&](auto&& f) { return f.DataPackageFormatId(); });
}

inline Windows::UI::ViewManagement::InputPane InputPane::GetForCurrentView()
{
    return impl::call_factory<InputPane, Windows::UI::ViewManagement::IInputPaneStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::UI::ViewManagement::InputPane InputPane::GetForUIContext(Windows::UI::UIContext const& context)
{
    return impl::call_factory<InputPane, Windows::UI::ViewManagement::IInputPaneStatics2>([&](auto&& f) { return f.GetForUIContext(context); });
}

inline Windows::Foundation::IAsyncAction ProjectionManager::StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.StartProjectingAsync(projectionViewId, anchorViewId); });
}

inline Windows::Foundation::IAsyncAction ProjectionManager::SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.SwapDisplaysForViewsAsync(projectionViewId, anchorViewId); });
}

inline Windows::Foundation::IAsyncAction ProjectionManager::StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.StopProjectingAsync(projectionViewId, anchorViewId); });
}

inline bool ProjectionManager::ProjectionDisplayAvailable()
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.ProjectionDisplayAvailable(); });
}

inline winrt::event_token ProjectionManager::ProjectionDisplayAvailableChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.ProjectionDisplayAvailableChanged(handler); });
}

inline ProjectionManager::ProjectionDisplayAvailableChanged_revoker ProjectionManager::ProjectionDisplayAvailableChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>();
    return { f, f.ProjectionDisplayAvailableChanged(handler) };
}

inline void ProjectionManager::ProjectionDisplayAvailableChanged(winrt::event_token const& token)
{
    impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics>([&](auto&& f) { return f.ProjectionDisplayAvailableChanged(token); });
}

inline Windows::Foundation::IAsyncAction ProjectionManager::StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Devices::Enumeration::DeviceInformation const& displayDeviceInfo)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics2>([&](auto&& f) { return f.StartProjectingAsync(projectionViewId, anchorViewId, displayDeviceInfo); });
}

inline Windows::Foundation::IAsyncOperation<bool> ProjectionManager::RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics2>([&](auto&& f) { return f.RequestStartProjectingAsync(projectionViewId, anchorViewId, selection); });
}

inline Windows::Foundation::IAsyncOperation<bool> ProjectionManager::RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& prefferedPlacement)
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics2>([&](auto&& f) { return f.RequestStartProjectingAsync(projectionViewId, anchorViewId, selection, prefferedPlacement); });
}

inline hstring ProjectionManager::GetDeviceSelector()
{
    return impl::call_factory<ProjectionManager, Windows::UI::ViewManagement::IProjectionManagerStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::UI::ViewManagement::StatusBar StatusBar::GetForCurrentView()
{
    return impl::call_factory<StatusBar, Windows::UI::ViewManagement::IStatusBarStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline UISettings::UISettings() :
    UISettings(impl::call_factory<UISettings>([](auto&& f) { return f.template ActivateInstance<UISettings>(); }))
{}

inline Windows::UI::ViewManagement::UIViewSettings UIViewSettings::GetForCurrentView()
{
    return impl::call_factory<UIViewSettings, Windows::UI::ViewManagement::IUIViewSettingsStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::UI::ViewManagement::ViewModePreferences ViewModePreferences::CreateDefault(Windows::UI::ViewManagement::ApplicationViewMode const& mode)
{
    return impl::call_factory<ViewModePreferences, Windows::UI::ViewManagement::IViewModePreferencesStatics>([&](auto&& f) { return f.CreateDefault(mode); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::ViewManagement::IAccessibilitySettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IAccessibilitySettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView3> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView3> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView4> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView4> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView7> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView7> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationView9> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationView9> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewScaling> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewScaling> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPane> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPane> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPane2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPane2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPaneControl> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPaneControl> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPaneStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPaneStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPaneStatics2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPaneStatics2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IStatusBar> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IStatusBar> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IStatusBarStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IStatusBarStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettings2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettings2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettings3> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettings3> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettings4> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettings4> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettings5> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettings5> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUIViewSettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUIViewSettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IViewModePreferences> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IViewModePreferences> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::AccessibilitySettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::AccessibilitySettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ActivationViewSwitcher> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ActivationViewSwitcher> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationView> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationView> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationViewScaling> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationViewScaling> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationViewSwitcher> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationViewSwitcher> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ApplicationViewTransferContext> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ApplicationViewTransferContext> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::InputPane> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::InputPane> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ProjectionManager> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ProjectionManager> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::StatusBar> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::StatusBar> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::UISettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::UISettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::UIViewSettings> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::UIViewSettings> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::ViewModePreferences> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::ViewModePreferences> {};

}
