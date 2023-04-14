// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.DragDrop.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
#include "winrt/impl/Windows.UI.Xaml.Input.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Animation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Imaging.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Media3D.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> double consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTrigger)->get_MinWindowWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowWidth(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTrigger)->put_MinWindowWidth(value));
}

template <typename D> double consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTrigger)->get_MinWindowHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IAdaptiveTrigger<D>::MinWindowHeight(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTrigger)->put_MinWindowHeight(value));
}

template <typename D> Windows::UI::Xaml::AdaptiveTrigger consume_Windows_UI_Xaml_IAdaptiveTriggerFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::AdaptiveTrigger value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTriggerFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IAdaptiveTriggerStatics<D>::MinWindowWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTriggerStatics)->get_MinWindowWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IAdaptiveTriggerStatics<D>::MinWindowHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IAdaptiveTriggerStatics)->get_MinWindowHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::ResourceDictionary consume_Windows_UI_Xaml_IApplication<D>::Resources() const
{
    Windows::UI::Xaml::ResourceDictionary value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->get_Resources(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::Resources(Windows::UI::Xaml::ResourceDictionary const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->put_Resources(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DebugSettings consume_Windows_UI_Xaml_IApplication<D>::DebugSettings() const
{
    Windows::UI::Xaml::DebugSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->get_DebugSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::ApplicationTheme consume_Windows_UI_Xaml_IApplication<D>::RequestedTheme() const
{
    Windows::UI::Xaml::ApplicationTheme value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->get_RequestedTheme(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::RequestedTheme(Windows::UI::Xaml::ApplicationTheme const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->put_RequestedTheme(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(Windows::UI::Xaml::UnhandledExceptionEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->add_UnhandledException(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::UnhandledException_revoker consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(auto_revoke_t, Windows::UI::Xaml::UnhandledExceptionEventHandler const& handler) const
{
    return impl::make_event_revoker<D, UnhandledException_revoker>(this, UnhandledException(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::UnhandledException(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IApplication)->remove_UnhandledException(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IApplication<D>::Suspending(Windows::UI::Xaml::SuspendingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->add_Suspending(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::Suspending_revoker consume_Windows_UI_Xaml_IApplication<D>::Suspending(auto_revoke_t, Windows::UI::Xaml::SuspendingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Suspending_revoker>(this, Suspending(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::Suspending(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IApplication)->remove_Suspending(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IApplication<D>::Resuming(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->add_Resuming(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IApplication<D>::Resuming_revoker consume_Windows_UI_Xaml_IApplication<D>::Resuming(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Resuming_revoker>(this, Resuming(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::Resuming(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IApplication)->remove_Resuming(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication<D>::Exit() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication)->Exit());
}

template <typename D> Windows::UI::Xaml::FocusVisualKind consume_Windows_UI_Xaml_IApplication2<D>::FocusVisualKind() const
{
    Windows::UI::Xaml::FocusVisualKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->get_FocusVisualKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplication2<D>::FocusVisualKind(Windows::UI::Xaml::FocusVisualKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->put_FocusVisualKind(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ApplicationRequiresPointerMode consume_Windows_UI_Xaml_IApplication2<D>::RequiresPointerMode() const
{
    Windows::UI::Xaml::ApplicationRequiresPointerMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->get_RequiresPointerMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplication2<D>::RequiresPointerMode(Windows::UI::Xaml::ApplicationRequiresPointerMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->put_RequiresPointerMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(Windows::UI::Xaml::LeavingBackgroundEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->add_LeavingBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground_revoker consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(auto_revoke_t, Windows::UI::Xaml::LeavingBackgroundEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LeavingBackground_revoker>(this, LeavingBackground(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication2<D>::LeavingBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IApplication2)->remove_LeavingBackground(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(Windows::UI::Xaml::EnteredBackgroundEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication2)->add_EnteredBackground(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground_revoker consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(auto_revoke_t, Windows::UI::Xaml::EnteredBackgroundEventHandler const& handler) const
{
    return impl::make_event_revoker<D, EnteredBackground_revoker>(this, EnteredBackground(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IApplication2<D>::EnteredBackground(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IApplication2)->remove_EnteredBackground(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::ApplicationHighContrastAdjustment consume_Windows_UI_Xaml_IApplication3<D>::HighContrastAdjustment() const
{
    Windows::UI::Xaml::ApplicationHighContrastAdjustment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication3)->get_HighContrastAdjustment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplication3<D>::HighContrastAdjustment(Windows::UI::Xaml::ApplicationHighContrastAdjustment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplication3)->put_HighContrastAdjustment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Application consume_Windows_UI_Xaml_IApplicationFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Application value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnActivated(Windows::ApplicationModel::Activation::IActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnLaunched(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileActivated(Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnFileActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnSearchActivated(Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnSearchActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnShareTargetActivated(Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnShareTargetActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileOpenPickerActivated(Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnFileOpenPickerActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnFileSavePickerActivated(Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnFileSavePickerActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnCachedFileUpdaterActivated(Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnCachedFileUpdaterActivated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides<D>::OnWindowCreated(Windows::UI::Xaml::WindowCreatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides)->OnWindowCreated(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationOverrides2<D>::OnBackgroundActivated(Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationOverrides2)->OnBackgroundActivated(get_abi(args)));
}

template <typename D> Windows::UI::Xaml::Application consume_Windows_UI_Xaml_IApplicationStatics<D>::Current() const
{
    Windows::UI::Xaml::Application value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationStatics<D>::Start(Windows::UI::Xaml::ApplicationInitializationCallback const& callback) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationStatics)->Start(get_abi(callback)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationStatics<D>::LoadComponent(Windows::Foundation::IInspectable const& component, Windows::Foundation::Uri const& resourceLocator) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationStatics)->LoadComponent(get_abi(component), get_abi(resourceLocator)));
}

template <typename D> void consume_Windows_UI_Xaml_IApplicationStatics<D>::LoadComponent(Windows::Foundation::IInspectable const& component, Windows::Foundation::Uri const& resourceLocator, Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const& componentResourceLocation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IApplicationStatics)->LoadComponentWithResourceLocation(get_abi(component), get_abi(resourceLocator), get_abi(componentResourceLocation)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IBindingFailedEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBindingFailedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::AnimationDesired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions)->get_AnimationDesired(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::AnimationDesired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions)->put_AnimationDesired(value));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Rect> consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::TargetRect() const
{
    Windows::Foundation::IReference<Windows::Foundation::Rect> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions)->get_TargetRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions<D>::TargetRect(optional<Windows::Foundation::Rect> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions)->put_TargetRect(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalAlignmentRatio() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->get_HorizontalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalAlignmentRatio(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->put_HorizontalAlignmentRatio(value));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalAlignmentRatio() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->get_VerticalAlignmentRatio(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalAlignmentRatio(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->put_VerticalAlignmentRatio(value));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::HorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->put_HorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->get_VerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewOptions2<D>::VerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewOptions2)->put_VerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetElement() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_TargetElement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetElement(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_TargetElement(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::AnimationDesired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_AnimationDesired(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::AnimationDesired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_AnimationDesired(value));
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_TargetRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::TargetRect(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_TargetRect(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalAlignmentRatio() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_HorizontalAlignmentRatio(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalAlignmentRatio() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_VerticalAlignmentRatio(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_HorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::HorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_HorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_VerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::VerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_VerticalOffset(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBringIntoViewRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBringIntoViewRequestedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_IBrushTransition<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBrushTransition)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IBrushTransition<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBrushTransition)->put_Duration(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::BrushTransition consume_Windows_UI_Xaml_IBrushTransitionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::BrushTransition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IBrushTransitionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_AltHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_AltHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_AltLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_AltLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMedium() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_AltMedium(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMedium(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_AltMedium(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_AltMediumHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_AltMediumHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_AltMediumLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::AltMediumLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_AltMediumLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_BaseHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_BaseHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_BaseLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_BaseLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMedium() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_BaseMedium(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMedium(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_BaseMedium(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_BaseMediumHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_BaseMediumHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_BaseMediumLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::BaseMediumLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_BaseMediumLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeAltLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeAltLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeAltLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeAltLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMediumLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackMediumLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMediumLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackMediumLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMedium() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeBlackMedium(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeBlackMedium(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeBlackMedium(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeDisabledHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeDisabledHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeDisabledLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeDisabledLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeDisabledLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeHigh() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeHigh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeHigh(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeHigh(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMedium() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeMedium(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMedium(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeMedium(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMediumLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeMediumLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeMediumLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeMediumLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeWhite() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeWhite(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeWhite(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeWhite(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeGray() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ChromeGray(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ChromeGray(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ChromeGray(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListLow() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ListLow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListLow(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ListLow(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListMedium() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ListMedium(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ListMedium(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ListMedium(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::ErrorText() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_ErrorText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::ErrorText(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_ErrorText(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_UI_Xaml_IColorPaletteResources<D>::Accent() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->get_Accent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IColorPaletteResources<D>::Accent(optional<Windows::UI::Color> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResources)->put_Accent(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ColorPaletteResources consume_Windows_UI_Xaml_IColorPaletteResourcesFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::ColorPaletteResources value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IColorPaletteResourcesFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::CornerRadius consume_Windows_UI_Xaml_ICornerRadiusHelperStatics<D>::FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft) const
{
    Windows::UI::Xaml::CornerRadius result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ICornerRadiusHelperStatics)->FromRadii(topLeft, topRight, bottomRight, bottomLeft, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::CornerRadius consume_Windows_UI_Xaml_ICornerRadiusHelperStatics<D>::FromUniformRadius(double uniformRadius) const
{
    Windows::UI::Xaml::CornerRadius result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ICornerRadiusHelperStatics)->FromUniformRadius(uniformRadius, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::NewValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataContextChangedEventArgs)->get_NewValue(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataContextChangedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDataContextChangedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataContextChangedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IDataTemplate<D>::LoadContent() const
{
    Windows::UI::Xaml::DependencyObject result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplate)->LoadContent(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ResetTemplate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateExtension)->ResetTemplate());
}

template <typename D> bool consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ProcessBinding(uint32_t phase) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateExtension)->ProcessBinding(phase, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_IDataTemplateExtension<D>::ProcessBindings(Windows::UI::Xaml::Controls::ContainerContentChangingEventArgs const& arg) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateExtension)->ProcessBindings(get_abi(arg), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::DataTemplate consume_Windows_UI_Xaml_IDataTemplateFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DataTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDataTemplateKey<D>::DataType() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateKey)->get_DataType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDataTemplateKey<D>::DataType(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateKey)->put_DataType(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DataTemplateKey consume_Windows_UI_Xaml_IDataTemplateKeyFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DataTemplateKey value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateKeyFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DataTemplateKey consume_Windows_UI_Xaml_IDataTemplateKeyFactory<D>::CreateInstanceWithType(Windows::Foundation::IInspectable const& dataType, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DataTemplateKey value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateKeyFactory)->CreateInstanceWithType(get_abi(dataType), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::ExtensionInstanceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateStatics2)->get_ExtensionInstanceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::IDataTemplateExtension consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::GetExtensionInstance(Windows::UI::Xaml::FrameworkElement const& element) const
{
    Windows::UI::Xaml::IDataTemplateExtension result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateStatics2)->GetExtensionInstance(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IDataTemplateStatics2<D>::SetExtensionInstance(Windows::UI::Xaml::FrameworkElement const& element, Windows::UI::Xaml::IDataTemplateExtension const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDataTemplateStatics2)->SetExtensionInstance(get_abi(element), get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings<D>::EnableFrameRateCounter() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->get_EnableFrameRateCounter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings<D>::EnableFrameRateCounter(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->put_EnableFrameRateCounter(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings<D>::IsBindingTracingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->get_IsBindingTracingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings<D>::IsBindingTracingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->put_IsBindingTracingEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings<D>::IsOverdrawHeatMapEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->get_IsOverdrawHeatMapEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings<D>::IsOverdrawHeatMapEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->put_IsOverdrawHeatMapEnabled(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(Windows::UI::Xaml::BindingFailedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->add_BindingFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed_revoker consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(auto_revoke_t, Windows::UI::Xaml::BindingFailedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, BindingFailed_revoker>(this, BindingFailed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings<D>::BindingFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IDebugSettings)->remove_BindingFailed(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings2<D>::EnableRedrawRegions() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings2)->get_EnableRedrawRegions(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings2<D>::EnableRedrawRegions(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings2)->put_EnableRedrawRegions(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings3<D>::IsTextPerformanceVisualizationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings3)->get_IsTextPerformanceVisualizationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings3<D>::IsTextPerformanceVisualizationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings3)->put_IsTextPerformanceVisualizationEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDebugSettings4<D>::FailFastOnErrors() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings4)->get_FailFastOnErrors(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDebugSettings4<D>::FailFastOnErrors(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDebugSettings4)->put_FailFastOnErrors(value));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyObject<D>::GetValue(Windows::UI::Xaml::DependencyProperty const& dp) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->GetValue(get_abi(dp), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IDependencyObject<D>::SetValue(Windows::UI::Xaml::DependencyProperty const& dp, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->SetValue(get_abi(dp), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IDependencyObject<D>::ClearValue(Windows::UI::Xaml::DependencyProperty const& dp) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->ClearValue(get_abi(dp)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyObject<D>::ReadLocalValue(Windows::UI::Xaml::DependencyProperty const& dp) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->ReadLocalValue(get_abi(dp), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyObject<D>::GetAnimationBaseValue(Windows::UI::Xaml::DependencyProperty const& dp) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->GetAnimationBaseValue(get_abi(dp), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Xaml_IDependencyObject<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> int64_t consume_Windows_UI_Xaml_IDependencyObject2<D>::RegisterPropertyChangedCallback(Windows::UI::Xaml::DependencyProperty const& dp, Windows::UI::Xaml::DependencyPropertyChangedCallback const& callback) const
{
    int64_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject2)->RegisterPropertyChangedCallback(get_abi(dp), get_abi(callback), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IDependencyObject2<D>::UnregisterPropertyChangedCallback(Windows::UI::Xaml::DependencyProperty const& dp, int64_t token) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObject2)->UnregisterPropertyChangedCallback(get_abi(dp), token));
}

template <typename D> Windows::UI::Xaml::DependencyObjectCollection consume_Windows_UI_Xaml_IDependencyObjectCollectionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DependencyObjectCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObjectCollectionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IDependencyObjectFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyObjectFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IDependencyProperty<D>::GetMetadata(Windows::UI::Xaml::Interop::TypeName const& forType) const
{
    Windows::UI::Xaml::PropertyMetadata result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyProperty)->GetMetadata(get_abi(forType), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_Property(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::OldValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_OldValue(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyPropertyChangedEventArgs<D>::NewValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyChangedEventArgs)->get_NewValue(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::UnsetValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyStatics)->get_UnsetValue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::Register(param::hstring const& name, Windows::UI::Xaml::Interop::TypeName const& propertyType, Windows::UI::Xaml::Interop::TypeName const& ownerType, Windows::UI::Xaml::PropertyMetadata const& typeMetadata) const
{
    Windows::UI::Xaml::DependencyProperty result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyStatics)->Register(get_abi(name), get_abi(propertyType), get_abi(ownerType), get_abi(typeMetadata), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IDependencyPropertyStatics<D>::RegisterAttached(param::hstring const& name, Windows::UI::Xaml::Interop::TypeName const& propertyType, Windows::UI::Xaml::Interop::TypeName const& ownerType, Windows::UI::Xaml::PropertyMetadata const& defaultMetadata) const
{
    Windows::UI::Xaml::DependencyProperty result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDependencyPropertyStatics)->RegisterAttached(get_abi(name), get_abi(propertyType), get_abi(ownerType), get_abi(defaultMetadata), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_IDispatcherTimer<D>::Interval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->get_Interval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDispatcherTimer<D>::Interval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->put_Interval(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IDispatcherTimer<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->get_IsEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->add_Tick(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick_revoker consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Tick_revoker>(this, Tick(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IDispatcherTimer<D>::Tick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->remove_Tick(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IDispatcherTimer<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->Start());
}

template <typename D> void consume_Windows_UI_Xaml_IDispatcherTimer<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimer)->Stop());
}

template <typename D> Windows::UI::Xaml::DispatcherTimer consume_Windows_UI_Xaml_IDispatcherTimerFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::DispatcherTimer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDispatcherTimerFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IDragEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs)->put_Handled(value));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackage consume_Windows_UI_Xaml_IDragEventArgs<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragEventArgs<D>::Data(Windows::ApplicationModel::DataTransfer::DataPackage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs)->put_Data(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_IDragEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageView consume_Windows_UI_Xaml_IDragEventArgs2<D>::DataView() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->get_DataView(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DragUIOverride consume_Windows_UI_Xaml_IDragEventArgs2<D>::DragUIOverride() const
{
    Windows::UI::Xaml::DragUIOverride value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->get_DragUIOverride(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers consume_Windows_UI_Xaml_IDragEventArgs2<D>::Modifiers() const
{
    Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->get_Modifiers(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_UI_Xaml_IDragEventArgs2<D>::AcceptedOperation() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->get_AcceptedOperation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragEventArgs2<D>::AcceptedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->put_AcceptedOperation(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DragOperationDeferral consume_Windows_UI_Xaml_IDragEventArgs2<D>::GetDeferral() const
{
    Windows::UI::Xaml::DragOperationDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs2)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_UI_Xaml_IDragEventArgs3<D>::AllowedOperations() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragEventArgs3)->get_AllowedOperations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragOperationDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragOperationDeferral)->Complete());
}

template <typename D> bool consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->put_Cancel(value));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackage consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::Data() const
{
    Windows::ApplicationModel::DataTransfer::DataPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->get_Data(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DragUI consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::DragUI() const
{
    Windows::UI::Xaml::DragUI value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->get_DragUI(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DragOperationDeferral consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::GetDeferral() const
{
    Windows::UI::Xaml::DragOperationDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_IDragStartingEventArgs<D>::GetPosition(Windows::UI::Xaml::UIElement const& relativeTo) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs)->GetPosition(get_abi(relativeTo), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_UI_Xaml_IDragStartingEventArgs2<D>::AllowedOperations() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs2)->get_AllowedOperations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragStartingEventArgs2<D>::AllowedOperations(Windows::ApplicationModel::DataTransfer::DataPackageOperation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragStartingEventArgs2)->put_AllowedOperations(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromBitmapImage(Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUI)->SetContentFromBitmapImage(get_abi(bitmapImage)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromBitmapImage(Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage, Windows::Foundation::Point const& anchorPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUI)->SetContentFromBitmapImageWithAnchorPoint(get_abi(bitmapImage), get_abi(anchorPoint)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUI)->SetContentFromSoftwareBitmap(get_abi(softwareBitmap)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap, Windows::Foundation::Point const& anchorPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUI)->SetContentFromSoftwareBitmapWithAnchorPoint(get_abi(softwareBitmap), get_abi(anchorPoint)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUI<D>::SetContentFromDataPackage() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUI)->SetContentFromDataPackage());
}

template <typename D> hstring consume_Windows_UI_Xaml_IDragUIOverride<D>::Caption() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->get_Caption(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::Caption(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->put_Caption(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IDragUIOverride<D>::IsContentVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->get_IsContentVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::IsContentVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->put_IsContentVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDragUIOverride<D>::IsCaptionVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->get_IsCaptionVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::IsCaptionVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->put_IsCaptionVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IDragUIOverride<D>::IsGlyphVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->get_IsGlyphVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::IsGlyphVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->put_IsGlyphVisible(value));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->Clear());
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromBitmapImage(Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->SetContentFromBitmapImage(get_abi(bitmapImage)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromBitmapImage(Windows::UI::Xaml::Media::Imaging::BitmapImage const& bitmapImage, Windows::Foundation::Point const& anchorPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->SetContentFromBitmapImageWithAnchorPoint(get_abi(bitmapImage), get_abi(anchorPoint)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->SetContentFromSoftwareBitmap(get_abi(softwareBitmap)));
}

template <typename D> void consume_Windows_UI_Xaml_IDragUIOverride<D>::SetContentFromSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap, Windows::Foundation::Point const& anchorPoint) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDragUIOverride)->SetContentFromSoftwareBitmapWithAnchorPoint(get_abi(softwareBitmap), get_abi(anchorPoint)));
}

template <typename D> Windows::ApplicationModel::DataTransfer::DataPackageOperation consume_Windows_UI_Xaml_IDropCompletedEventArgs<D>::DropResult() const
{
    Windows::ApplicationModel::DataTransfer::DataPackageOperation value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDropCompletedEventArgs)->get_DropResult(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Automatic() const
{
    Windows::UI::Xaml::Duration value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->get_Automatic(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Forever() const
{
    Windows::UI::Xaml::Duration value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->get_Forever(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Compare(Windows::UI::Xaml::Duration const& duration1, Windows::UI::Xaml::Duration const& duration2) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->Compare(get_abi(duration1), get_abi(duration2), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IDurationHelperStatics<D>::FromTimeSpan(Windows::Foundation::TimeSpan const& timeSpan) const
{
    Windows::UI::Xaml::Duration result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->FromTimeSpan(get_abi(timeSpan), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IDurationHelperStatics<D>::GetHasTimeSpan(Windows::UI::Xaml::Duration const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->GetHasTimeSpan(get_abi(target), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Add(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& duration) const
{
    Windows::UI::Xaml::Duration result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->Add(get_abi(target), get_abi(duration), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Equals(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IDurationHelperStatics<D>::Subtract(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& duration) const
{
    Windows::UI::Xaml::Duration result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IDurationHelperStatics)->Subtract(get_abi(target), get_abi(duration), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::EffectiveViewport() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_EffectiveViewport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::MaxViewport() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_MaxViewport(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::BringIntoViewDistanceX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_BringIntoViewDistanceX(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IEffectiveViewportChangedEventArgs<D>::BringIntoViewDistanceY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEffectiveViewportChangedEventArgs)->get_BringIntoViewDistanceY(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IElementFactory<D>::GetElement(Windows::UI::Xaml::ElementFactoryGetArgs const& args) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactory)->GetElement(get_abi(args), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IElementFactory<D>::RecycleElement(Windows::UI::Xaml::ElementFactoryRecycleArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactory)->RecycleElement(get_abi(args)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Data() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryGetArgs)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Data(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryGetArgs)->put_Data(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Parent() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryGetArgs)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementFactoryGetArgs<D>::Parent(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryGetArgs)->put_Parent(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ElementFactoryGetArgs consume_Windows_UI_Xaml_IElementFactoryGetArgsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::ElementFactoryGetArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryGetArgsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Element() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryRecycleArgs)->get_Element(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Element(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryRecycleArgs)->put_Element(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Parent() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryRecycleArgs)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementFactoryRecycleArgs<D>::Parent(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryRecycleArgs)->put_Parent(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ElementFactoryRecycleArgs consume_Windows_UI_Xaml_IElementFactoryRecycleArgsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::ElementFactoryRecycleArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementFactoryRecycleArgsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Volume() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics)->get_Volume(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Volume(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics)->put_Volume(value));
}

template <typename D> Windows::UI::Xaml::ElementSoundPlayerState consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::State() const
{
    Windows::UI::Xaml::ElementSoundPlayerState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::State(Windows::UI::Xaml::ElementSoundPlayerState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics)->put_State(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IElementSoundPlayerStatics<D>::Play(Windows::UI::Xaml::ElementSoundKind const& sound) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics)->Play(get_abi(sound)));
}

template <typename D> Windows::UI::Xaml::ElementSpatialAudioMode consume_Windows_UI_Xaml_IElementSoundPlayerStatics2<D>::SpatialAudioMode() const
{
    Windows::UI::Xaml::ElementSpatialAudioMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics2)->get_SpatialAudioMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IElementSoundPlayerStatics2<D>::SpatialAudioMode(Windows::UI::Xaml::ElementSpatialAudioMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IElementSoundPlayerStatics2)->put_SpatialAudioMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IEventTrigger<D>::RoutedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEventTrigger)->get_RoutedEvent(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IEventTrigger<D>::RoutedEvent(Windows::UI::Xaml::RoutedEvent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEventTrigger)->put_RoutedEvent(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::TriggerActionCollection consume_Windows_UI_Xaml_IEventTrigger<D>::Actions() const
{
    Windows::UI::Xaml::TriggerActionCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IEventTrigger)->get_Actions(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_IExceptionRoutedEventArgs<D>::ErrorMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IExceptionRoutedEventArgs)->get_ErrorMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::TriggerCollection consume_Windows_UI_Xaml_IFrameworkElement<D>::Triggers() const
{
    Windows::UI::Xaml::TriggerCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Triggers(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::ResourceDictionary consume_Windows_UI_Xaml_IFrameworkElement<D>::Resources() const
{
    Windows::UI::Xaml::ResourceDictionary value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Resources(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Resources(Windows::UI::Xaml::ResourceDictionary const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Resources(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IFrameworkElement<D>::Tag() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Tag(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Tag(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IFrameworkElement<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Language(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::ActualWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_ActualWidth(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::ActualHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_ActualHeight(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::Width() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Width(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Width(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Width(value));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::Height() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Height(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Height(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Height(value));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::MinWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_MinWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::MinWidth(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_MinWidth(value));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_MaxWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxWidth(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_MaxWidth(value));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::MinHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_MinHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::MinHeight(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_MinHeight(value));
}

template <typename D> double consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_MaxHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::MaxHeight(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_MaxHeight(value));
}

template <typename D> Windows::UI::Xaml::HorizontalAlignment consume_Windows_UI_Xaml_IFrameworkElement<D>::HorizontalAlignment() const
{
    Windows::UI::Xaml::HorizontalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_HorizontalAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::HorizontalAlignment(Windows::UI::Xaml::HorizontalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_HorizontalAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::VerticalAlignment consume_Windows_UI_Xaml_IFrameworkElement<D>::VerticalAlignment() const
{
    Windows::UI::Xaml::VerticalAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_VerticalAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::VerticalAlignment(Windows::UI::Xaml::VerticalAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_VerticalAlignment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IFrameworkElement<D>::Margin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Margin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Margin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Margin(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IFrameworkElement<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Name(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_IFrameworkElement<D>::BaseUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_BaseUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IFrameworkElement<D>::DataContext() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_DataContext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::DataContext(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_DataContext(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Style consume_Windows_UI_Xaml_IFrameworkElement<D>::Style() const
{
    Windows::UI::Xaml::Style value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Style(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Style(Windows::UI::Xaml::Style const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_Style(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IFrameworkElement<D>::Parent() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FlowDirection consume_Windows_UI_Xaml_IFrameworkElement<D>::FlowDirection() const
{
    Windows::UI::Xaml::FlowDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->get_FlowDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::FlowDirection(Windows::UI::Xaml::FlowDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->put_FlowDirection(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->add_Loaded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Loaded_revoker>(this, Loaded(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Loaded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->remove_Loaded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->add_Unloaded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Unloaded_revoker>(this, Unloaded(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::Unloaded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->remove_Unloaded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(Windows::UI::Xaml::SizeChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->add_SizeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(auto_revoke_t, Windows::UI::Xaml::SizeChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::SizeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->remove_SizeChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->add_LayoutUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated_revoker consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LayoutUpdated_revoker>(this, LayoutUpdated(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::LayoutUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->remove_LayoutUpdated(get_abi(token)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IFrameworkElement<D>::FindName(param::hstring const& name) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->FindName(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement<D>::SetBinding(Windows::UI::Xaml::DependencyProperty const& dp, Windows::UI::Xaml::Data::BindingBase const& binding) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement)->SetBinding(get_abi(dp), get_abi(binding)));
}

template <typename D> Windows::UI::Xaml::ElementTheme consume_Windows_UI_Xaml_IFrameworkElement2<D>::RequestedTheme() const
{
    Windows::UI::Xaml::ElementTheme value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement2)->get_RequestedTheme(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement2<D>::RequestedTheme(Windows::UI::Xaml::ElementTheme const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement2)->put_RequestedTheme(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::DataContextChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement2)->add_DataContextChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::DataContextChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DataContextChanged_revoker>(this, DataContextChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement2<D>::DataContextChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement2)->remove_DataContextChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Data::BindingExpression consume_Windows_UI_Xaml_IFrameworkElement2<D>::GetBindingExpression(Windows::UI::Xaml::DependencyProperty const& dp) const
{
    Windows::UI::Xaml::Data::BindingExpression result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement2)->GetBindingExpression(get_abi(dp), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement3)->add_Loading(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading_revoker consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Loading_revoker>(this, Loading(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement3<D>::Loading(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement3)->remove_Loading(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusOnInteraction() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_AllowFocusOnInteraction(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusOnInteraction(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_AllowFocusOnInteraction(value));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualMargin() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualMargin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualMargin(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualMargin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualSecondaryThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryThickness(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualSecondaryThickness(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryThickness() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualPrimaryThickness(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryThickness(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualPrimaryThickness(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualSecondaryBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualSecondaryBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualSecondaryBrush(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Brush consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryBrush() const
{
    Windows::UI::Xaml::Media::Brush value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_FocusVisualPrimaryBrush(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::FocusVisualPrimaryBrush(Windows::UI::Xaml::Media::Brush const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_FocusVisualPrimaryBrush(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusWhenDisabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->get_AllowFocusWhenDisabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement4<D>::AllowFocusWhenDisabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement4)->put_AllowFocusWhenDisabled(value));
}

template <typename D> Windows::UI::Xaml::ElementTheme consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualTheme() const
{
    Windows::UI::Xaml::ElementTheme value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement6)->get_ActualTheme(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement6)->add_ActualThemeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ActualThemeChanged_revoker>(this, ActualThemeChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement6<D>::ActualThemeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement6)->remove_ActualThemeChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_IFrameworkElement7<D>::IsLoaded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement7)->get_IsLoaded(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement7)->add_EffectiveViewportChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged_revoker consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EffectiveViewportChanged_revoker>(this, EffectiveViewportChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElement7<D>::EffectiveViewportChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IFrameworkElement7)->remove_EffectiveViewportChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::FrameworkElement consume_Windows_UI_Xaml_IFrameworkElementFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::FrameworkElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::MeasureOverride(Windows::Foundation::Size const& availableSize) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementOverrides)->MeasureOverride(get_abi(availableSize), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::ArrangeOverride(Windows::Foundation::Size const& finalSize) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementOverrides)->ArrangeOverride(get_abi(finalSize), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElementOverrides<D>::OnApplyTemplate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementOverrides)->OnApplyTemplate());
}

template <typename D> bool consume_Windows_UI_Xaml_IFrameworkElementOverrides2<D>::GoToElementStateCore(param::hstring const& stateName, bool useTransitions) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementOverrides2)->GoToElementStateCore(get_abi(stateName), useTransitions, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElementProtected7<D>::InvalidateViewport() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementProtected7)->InvalidateViewport());
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::TagProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_TagProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::LanguageProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_LanguageProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::ActualWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_ActualWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::ActualHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_ActualHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::WidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_WidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::HeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_HeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MinWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_MinWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MaxWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_MaxWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MinHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_MinHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MaxHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_MaxHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::HorizontalAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_HorizontalAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::VerticalAlignmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_VerticalAlignmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::MarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_MarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::NameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_NameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::DataContextProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_DataContextProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::StyleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_StyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics<D>::FlowDirectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics)->get_FlowDirectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics2<D>::RequestedThemeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics2)->get_RequestedThemeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::AllowFocusOnInteractionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_AllowFocusOnInteractionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualMarginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualMarginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualSecondaryThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualSecondaryThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualPrimaryThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualPrimaryThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualSecondaryBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualSecondaryBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::FocusVisualPrimaryBrushProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_FocusVisualPrimaryBrushProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics4<D>::AllowFocusWhenDisabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics4)->get_AllowFocusWhenDisabledProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IFrameworkElementStatics5<D>::DeferTree(Windows::UI::Xaml::DependencyObject const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics5)->DeferTree(get_abi(element)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IFrameworkElementStatics6<D>::ActualThemeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkElementStatics6)->get_ActualThemeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::FrameworkTemplate consume_Windows_UI_Xaml_IFrameworkTemplateFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::FrameworkTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IFrameworkTemplateFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::Auto() const
{
    Windows::UI::Xaml::GridLength value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->get_Auto(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::FromPixels(double pixels) const
{
    Windows::UI::Xaml::GridLength result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->FromPixels(pixels, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::GridLength consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::FromValueAndType(double value, Windows::UI::Xaml::GridUnitType const& type) const
{
    Windows::UI::Xaml::GridLength result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->FromValueAndType(value, get_abi(type), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsAbsolute(Windows::UI::Xaml::GridLength const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsAbsolute(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsAuto(Windows::UI::Xaml::GridLength const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsAuto(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::GetIsStar(Windows::UI::Xaml::GridLength const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->GetIsStar(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IGridLengthHelperStatics<D>::Equals(Windows::UI::Xaml::GridLength const& target, Windows::UI::Xaml::GridLength const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IGridLengthHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_IMediaFailedRoutedEventArgs<D>::ErrorTrace() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IMediaFailedRoutedEventArgs)->get_ErrorTrace(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_IPointHelperStatics<D>::FromCoordinates(float x, float y) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPointHelperStatics)->FromCoordinates(x, y, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IPropertyMetadata<D>::DefaultValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadata)->get_DefaultValue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::CreateDefaultValueCallback consume_Windows_UI_Xaml_IPropertyMetadata<D>::CreateDefaultValueCallback() const
{
    Windows::UI::Xaml::CreateDefaultValueCallback value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadata)->get_CreateDefaultValueCallback(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataFactory<D>::CreateInstanceWithDefaultValue(Windows::Foundation::IInspectable const& defaultValue, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::PropertyMetadata value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataFactory)->CreateInstanceWithDefaultValue(get_abi(defaultValue), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataFactory<D>::CreateInstanceWithDefaultValueAndCallback(Windows::Foundation::IInspectable const& defaultValue, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::PropertyMetadata value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataFactory)->CreateInstanceWithDefaultValueAndCallback(get_abi(defaultValue), get_abi(propertyChangedCallback), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(Windows::Foundation::IInspectable const& defaultValue) const
{
    Windows::UI::Xaml::PropertyMetadata result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithDefaultValue(get_abi(defaultValue), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(Windows::Foundation::IInspectable const& defaultValue, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback) const
{
    Windows::UI::Xaml::PropertyMetadata result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithDefaultValueAndCallback(get_abi(defaultValue), get_abi(propertyChangedCallback), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback) const
{
    Windows::UI::Xaml::PropertyMetadata result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithFactory(get_abi(createDefaultValueCallback), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::PropertyMetadata consume_Windows_UI_Xaml_IPropertyMetadataStatics<D>::Create(Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback) const
{
    Windows::UI::Xaml::PropertyMetadata result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyMetadataStatics)->CreateWithFactoryAndCallback(get_abi(createDefaultValueCallback), get_abi(propertyChangedCallback), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_IPropertyPath<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyPath)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyPath consume_Windows_UI_Xaml_IPropertyPathFactory<D>::CreateInstance(param::hstring const& path) const
{
    Windows::UI::Xaml::PropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IPropertyPathFactory)->CreateInstance(get_abi(path), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::Empty() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->get_Empty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromCoordinatesAndDimensions(float x, float y, float width, float height) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->FromCoordinatesAndDimensions(x, y, width, height, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromPoints(Windows::Foundation::Point const& point1, Windows::Foundation::Point const& point2) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->FromPoints(get_abi(point1), get_abi(point2), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::FromLocationAndSize(Windows::Foundation::Point const& location, Windows::Foundation::Size const& size) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->FromLocationAndSize(get_abi(location), get_abi(size), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetIsEmpty(Windows::Foundation::Rect const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->GetIsEmpty(get_abi(target), &result));
    return result;
}

template <typename D> float consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetBottom(Windows::Foundation::Rect const& target) const
{
    float result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->GetBottom(get_abi(target), &result));
    return result;
}

template <typename D> float consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetLeft(Windows::Foundation::Rect const& target) const
{
    float result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->GetLeft(get_abi(target), &result));
    return result;
}

template <typename D> float consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetRight(Windows::Foundation::Rect const& target) const
{
    float result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->GetRight(get_abi(target), &result));
    return result;
}

template <typename D> float consume_Windows_UI_Xaml_IRectHelperStatics<D>::GetTop(Windows::Foundation::Rect const& target) const
{
    float result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->GetTop(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IRectHelperStatics<D>::Contains(Windows::Foundation::Rect const& target, Windows::Foundation::Point const& point) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->Contains(get_abi(target), get_abi(point), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IRectHelperStatics<D>::Equals(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::Intersect(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& rect) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->Intersect(get_abi(target), get_abi(rect), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::Union(Windows::Foundation::Rect const& target, Windows::Foundation::Point const& point) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->UnionWithPoint(get_abi(target), get_abi(point), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IRectHelperStatics<D>::Union(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& rect) const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRectHelperStatics)->UnionWithRect(get_abi(target), get_abi(rect), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_IResourceDictionary<D>::Source() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IResourceDictionary)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IResourceDictionary<D>::Source(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IResourceDictionary)->put_Source(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::ResourceDictionary> consume_Windows_UI_Xaml_IResourceDictionary<D>::MergedDictionaries() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::ResourceDictionary> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IResourceDictionary)->get_MergedDictionaries(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_IResourceDictionary<D>::ThemeDictionaries() const
{
    Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IResourceDictionary)->get_ThemeDictionaries(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::ResourceDictionary consume_Windows_UI_Xaml_IResourceDictionaryFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::ResourceDictionary value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IResourceDictionaryFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_IRoutedEventArgs<D>::OriginalSource() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRoutedEventArgs)->get_OriginalSource(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEventArgs consume_Windows_UI_Xaml_IRoutedEventArgsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::RoutedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IRoutedEventArgsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_IScalarTransition<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IScalarTransition)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IScalarTransition<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IScalarTransition)->put_Duration(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ScalarTransition consume_Windows_UI_Xaml_IScalarTransitionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::ScalarTransition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IScalarTransitionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_ISetter<D>::Property() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter)->get_Property(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_ISetter<D>::Property(Windows::UI::Xaml::DependencyProperty const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter)->put_Property(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_ISetter<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_ISetter<D>::Value(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter)->put_Value(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::TargetPropertyPath consume_Windows_UI_Xaml_ISetter2<D>::Target() const
{
    Windows::UI::Xaml::TargetPropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter2)->get_Target(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_ISetter2<D>::Target(Windows::UI::Xaml::TargetPropertyPath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetter2)->put_Target(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_ISetterBase<D>::IsSealed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetterBase)->get_IsSealed(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_ISetterBaseCollection<D>::IsSealed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetterBaseCollection)->get_IsSealed(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Setter consume_Windows_UI_Xaml_ISetterFactory<D>::CreateInstance(Windows::UI::Xaml::DependencyProperty const& targetProperty, Windows::Foundation::IInspectable const& value) const
{
    Windows::UI::Xaml::Setter instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISetterFactory)->CreateInstance(get_abi(targetProperty), get_abi(value), put_abi(instance)));
    return instance;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_ISizeChangedEventArgs<D>::PreviousSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeChangedEventArgs)->get_PreviousSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_ISizeChangedEventArgs<D>::NewSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeChangedEventArgs)->get_NewSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_ISizeHelperStatics<D>::Empty() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeHelperStatics)->get_Empty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_ISizeHelperStatics<D>::FromDimensions(float width, float height) const
{
    Windows::Foundation::Size result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeHelperStatics)->FromDimensions(width, height, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_ISizeHelperStatics<D>::GetIsEmpty(Windows::Foundation::Size const& target) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeHelperStatics)->GetIsEmpty(get_abi(target), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_ISizeHelperStatics<D>::Equals(Windows::Foundation::Size const& target, Windows::Foundation::Size const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ISizeHelperStatics)->Equals(get_abi(target), get_abi(value), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_IStateTrigger<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStateTrigger)->get_IsActive(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IStateTrigger<D>::IsActive(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStateTrigger)->put_IsActive(value));
}

template <typename D> Windows::UI::Xaml::StateTriggerBase consume_Windows_UI_Xaml_IStateTriggerBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::StateTriggerBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStateTriggerBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IStateTriggerBaseProtected<D>::SetActive(bool IsActive) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStateTriggerBaseProtected)->SetActive(IsActive));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IStateTriggerStatics<D>::IsActiveProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStateTriggerStatics)->get_IsActiveProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IStyle<D>::IsSealed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->get_IsSealed(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::SetterBaseCollection consume_Windows_UI_Xaml_IStyle<D>::Setters() const
{
    Windows::UI::Xaml::SetterBaseCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->get_Setters(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_IStyle<D>::TargetType() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->get_TargetType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IStyle<D>::TargetType(Windows::UI::Xaml::Interop::TypeName const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->put_TargetType(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Style consume_Windows_UI_Xaml_IStyle<D>::BasedOn() const
{
    Windows::UI::Xaml::Style value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->get_BasedOn(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IStyle<D>::BasedOn(Windows::UI::Xaml::Style const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->put_BasedOn(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IStyle<D>::Seal() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyle)->Seal());
}

template <typename D> Windows::UI::Xaml::Style consume_Windows_UI_Xaml_IStyleFactory<D>::CreateInstance(Windows::UI::Xaml::Interop::TypeName const& targetType) const
{
    Windows::UI::Xaml::Style value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IStyleFactory)->CreateInstance(get_abi(targetType), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::PropertyPath consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Path() const
{
    Windows::UI::Xaml::PropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ITargetPropertyPath)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Path(Windows::UI::Xaml::PropertyPath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ITargetPropertyPath)->put_Path(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Target() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ITargetPropertyPath)->get_Target(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_ITargetPropertyPath<D>::Target(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ITargetPropertyPath)->put_Target(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::TargetPropertyPath consume_Windows_UI_Xaml_ITargetPropertyPathFactory<D>::CreateInstance(Windows::UI::Xaml::DependencyProperty const& targetProperty) const
{
    Windows::UI::Xaml::TargetPropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::ITargetPropertyPathFactory)->CreateInstance(get_abi(targetProperty), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IThicknessHelperStatics<D>::FromLengths(double left, double top, double right, double bottom) const
{
    Windows::UI::Xaml::Thickness result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IThicknessHelperStatics)->FromLengths(left, top, right, bottom, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_IThicknessHelperStatics<D>::FromUniformLength(double uniformLength) const
{
    Windows::UI::Xaml::Thickness result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IThicknessHelperStatics)->FromUniformLength(uniformLength, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_IUIElement<D>::DesiredSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_DesiredSize(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::AllowDrop() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_AllowDrop(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::AllowDrop(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_AllowDrop(value));
}

template <typename D> double consume_Windows_UI_Xaml_IUIElement<D>::Opacity() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_Opacity(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Opacity(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_Opacity(value));
}

template <typename D> Windows::UI::Xaml::Media::RectangleGeometry consume_Windows_UI_Xaml_IUIElement<D>::Clip() const
{
    Windows::UI::Xaml::Media::RectangleGeometry value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_Clip(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Clip(Windows::UI::Xaml::Media::RectangleGeometry const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_Clip(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Transform consume_Windows_UI_Xaml_IUIElement<D>::RenderTransform() const
{
    Windows::UI::Xaml::Media::Transform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_RenderTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::RenderTransform(Windows::UI::Xaml::Media::Transform const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_RenderTransform(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Projection consume_Windows_UI_Xaml_IUIElement<D>::Projection() const
{
    Windows::UI::Xaml::Media::Projection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_Projection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Projection(Windows::UI::Xaml::Media::Projection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_Projection(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_IUIElement<D>::RenderTransformOrigin() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_RenderTransformOrigin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::RenderTransformOrigin(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_RenderTransformOrigin(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::IsHitTestVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_IsHitTestVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::IsHitTestVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_IsHitTestVisible(value));
}

template <typename D> Windows::UI::Xaml::Visibility consume_Windows_UI_Xaml_IUIElement<D>::Visibility() const
{
    Windows::UI::Xaml::Visibility value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_Visibility(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Visibility(Windows::UI::Xaml::Visibility const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_Visibility(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_IUIElement<D>::RenderSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_RenderSize(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::UseLayoutRounding() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_UseLayoutRounding(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::UseLayoutRounding(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_UseLayoutRounding(value));
}

template <typename D> Windows::UI::Xaml::Media::Animation::TransitionCollection consume_Windows_UI_Xaml_IUIElement<D>::Transitions() const
{
    Windows::UI::Xaml::Media::Animation::TransitionCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_Transitions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Transitions(Windows::UI::Xaml::Media::Animation::TransitionCollection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_Transitions(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::CacheMode consume_Windows_UI_Xaml_IUIElement<D>::CacheMode() const
{
    Windows::UI::Xaml::Media::CacheMode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_CacheMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::CacheMode(Windows::UI::Xaml::Media::CacheMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_CacheMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::IsTapEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_IsTapEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::IsTapEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_IsTapEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::IsDoubleTapEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_IsDoubleTapEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::IsDoubleTapEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_IsDoubleTapEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::IsRightTapEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_IsRightTapEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::IsRightTapEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_IsRightTapEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::IsHoldingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_IsHoldingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::IsHoldingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_IsHoldingEnabled(value));
}

template <typename D> Windows::UI::Xaml::Input::ManipulationModes consume_Windows_UI_Xaml_IUIElement<D>::ManipulationMode() const
{
    Windows::UI::Xaml::Input::ManipulationModes value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_ManipulationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationMode(Windows::UI::Xaml::Input::ManipulationModes const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->put_ManipulationMode(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Input::Pointer> consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptures() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Input::Pointer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->get_PointerCaptures(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_KeyUp(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::KeyUp_revoker consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(auto_revoke_t, Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    return impl::make_event_revoker<D, KeyUp_revoker>(this, KeyUp(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::KeyUp(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_KeyUp(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_KeyDown(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::KeyDown_revoker consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(auto_revoke_t, Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    return impl::make_event_revoker<D, KeyDown_revoker>(this, KeyDown(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::KeyDown(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_KeyDown(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::GotFocus_revoker consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_GotFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_LostFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::LostFocus_revoker consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::LostFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_LostFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(Windows::UI::Xaml::DragEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_DragEnter(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragEnter_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(auto_revoke_t, Windows::UI::Xaml::DragEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragEnter_revoker>(this, DragEnter(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::DragEnter(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_DragEnter(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(Windows::UI::Xaml::DragEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_DragLeave(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragLeave_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(auto_revoke_t, Windows::UI::Xaml::DragEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragLeave_revoker>(this, DragLeave(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::DragLeave(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_DragLeave(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::DragOver(Windows::UI::Xaml::DragEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_DragOver(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DragOver_revoker consume_Windows_UI_Xaml_IUIElement<D>::DragOver(auto_revoke_t, Windows::UI::Xaml::DragEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DragOver_revoker>(this, DragOver(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::DragOver(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_DragOver(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::Drop(Windows::UI::Xaml::DragEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_Drop(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Drop_revoker consume_Windows_UI_Xaml_IUIElement<D>::Drop(auto_revoke_t, Windows::UI::Xaml::DragEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Drop_revoker>(this, Drop(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Drop(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_Drop(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerPressed_revoker>(this, PointerPressed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerMoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerMoved_revoker>(this, PointerMoved(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerMoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerMoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerReleased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerReleased_revoker>(this, PointerReleased(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerReleased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerReleased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerEntered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerEntered_revoker>(this, PointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerExited_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerExited_revoker>(this, PointerExited(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerExited(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerCaptureLost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerCaptureLost_revoker>(this, PointerCaptureLost(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerCaptureLost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerCaptureLost(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerCanceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerCanceled_revoker>(this, PointerCanceled(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerCanceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerCanceled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_PointerWheelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged_revoker consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(auto_revoke_t, Windows::UI::Xaml::Input::PointerEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PointerWheelChanged_revoker>(this, PointerWheelChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::PointerWheelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_PointerWheelChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::Tapped(Windows::UI::Xaml::Input::TappedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_Tapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Tapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::Tapped(auto_revoke_t, Windows::UI::Xaml::Input::TappedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Tapped_revoker>(this, Tapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Tapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_Tapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(Windows::UI::Xaml::Input::DoubleTappedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_DoubleTapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(auto_revoke_t, Windows::UI::Xaml::Input::DoubleTappedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DoubleTapped_revoker>(this, DoubleTapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::DoubleTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_DoubleTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::Holding(Windows::UI::Xaml::Input::HoldingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_Holding(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::Holding_revoker consume_Windows_UI_Xaml_IUIElement<D>::Holding(auto_revoke_t, Windows::UI::Xaml::Input::HoldingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Holding_revoker>(this, Holding(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Holding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_Holding(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(Windows::UI::Xaml::Input::RightTappedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_RightTapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::RightTapped_revoker consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(auto_revoke_t, Windows::UI::Xaml::Input::RightTappedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, RightTapped_revoker>(this, RightTapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::RightTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_RightTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(Windows::UI::Xaml::Input::ManipulationStartingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_ManipulationStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(auto_revoke_t, Windows::UI::Xaml::Input::ManipulationStartingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ManipulationStarting_revoker>(this, ManipulationStarting(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_ManipulationStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_ManipulationInertiaStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(auto_revoke_t, Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ManipulationInertiaStarting_revoker>(this, ManipulationInertiaStarting(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationInertiaStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_ManipulationInertiaStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(Windows::UI::Xaml::Input::ManipulationStartedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_ManipulationStarted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(auto_revoke_t, Windows::UI::Xaml::Input::ManipulationStartedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ManipulationStarted_revoker>(this, ManipulationStarted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationStarted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_ManipulationStarted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_ManipulationDelta(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(auto_revoke_t, Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ManipulationDelta_revoker>(this, ManipulationDelta(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationDelta(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_ManipulationDelta(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->add_ManipulationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted_revoker consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(auto_revoke_t, Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ManipulationCompleted_revoker>(this, ManipulationCompleted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ManipulationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement)->remove_ManipulationCompleted(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Measure(Windows::Foundation::Size const& availableSize) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->Measure(get_abi(availableSize)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::Arrange(Windows::Foundation::Rect const& finalRect) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->Arrange(get_abi(finalRect)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement<D>::CapturePointer(Windows::UI::Xaml::Input::Pointer const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->CapturePointer(get_abi(value), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ReleasePointerCapture(Windows::UI::Xaml::Input::Pointer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->ReleasePointerCapture(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::ReleasePointerCaptures() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->ReleasePointerCaptures());
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::AddHandler(Windows::UI::Xaml::RoutedEvent const& routedEvent, Windows::Foundation::IInspectable const& handler, bool handledEventsToo) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->AddHandler(get_abi(routedEvent), get_abi(handler), handledEventsToo));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::RemoveHandler(Windows::UI::Xaml::RoutedEvent const& routedEvent, Windows::Foundation::IInspectable const& handler) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->RemoveHandler(get_abi(routedEvent), get_abi(handler)));
}

template <typename D> Windows::UI::Xaml::Media::GeneralTransform consume_Windows_UI_Xaml_IUIElement<D>::TransformToVisual(Windows::UI::Xaml::UIElement const& visual) const
{
    Windows::UI::Xaml::Media::GeneralTransform result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->TransformToVisual(get_abi(visual), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::InvalidateMeasure() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->InvalidateMeasure());
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::InvalidateArrange() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->InvalidateArrange());
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement<D>::UpdateLayout() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement)->UpdateLayout());
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_IUIElement10<D>::ActualOffset() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->get_ActualOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float2 consume_Windows_UI_Xaml_IUIElement10<D>::ActualSize() const
{
    Windows::Foundation::Numerics::float2 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->get_ActualSize(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::XamlRoot consume_Windows_UI_Xaml_IUIElement10<D>::XamlRoot() const
{
    Windows::UI::Xaml::XamlRoot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->get_XamlRoot(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement10<D>::XamlRoot(Windows::UI::Xaml::XamlRoot const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->put_XamlRoot(get_abi(value)));
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_Xaml_IUIElement10<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Shadow consume_Windows_UI_Xaml_IUIElement10<D>::Shadow() const
{
    Windows::UI::Xaml::Media::Shadow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->get_Shadow(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement10<D>::Shadow(Windows::UI::Xaml::Media::Shadow const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement10)->put_Shadow(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::ElementCompositeMode consume_Windows_UI_Xaml_IUIElement2<D>::CompositeMode() const
{
    Windows::UI::Xaml::Media::ElementCompositeMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement2)->get_CompositeMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement2<D>::CompositeMode(Windows::UI::Xaml::Media::ElementCompositeMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement2)->put_CompositeMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement2<D>::CancelDirectManipulations() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement2)->CancelDirectManipulations(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::Media::Media3D::Transform3D consume_Windows_UI_Xaml_IUIElement3<D>::Transform3D() const
{
    Windows::UI::Xaml::Media::Media3D::Transform3D value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->get_Transform3D(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement3<D>::Transform3D(Windows::UI::Xaml::Media::Media3D::Transform3D const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->put_Transform3D(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement3<D>::CanDrag() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->get_CanDrag(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement3<D>::CanDrag(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->put_CanDrag(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DragStartingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->add_DragStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting_revoker consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DragStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DragStarting_revoker>(this, DragStarting(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement3<D>::DragStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->remove_DragStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DropCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->add_DropCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted_revoker consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DropCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DropCompleted_revoker>(this, DropCompleted(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement3<D>::DropCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->remove_DropCompleted(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackageOperation> consume_Windows_UI_Xaml_IUIElement3<D>::StartDragAsync(Windows::UI::Input::PointerPoint const& pointerPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackageOperation> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement3)->StartDragAsync(get_abi(pointerPoint), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Controls::Primitives::FlyoutBase consume_Windows_UI_Xaml_IUIElement4<D>::ContextFlyout() const
{
    Windows::UI::Xaml::Controls::Primitives::FlyoutBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->get_ContextFlyout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::ContextFlyout(Windows::UI::Xaml::Controls::Primitives::FlyoutBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->put_ContextFlyout(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement4<D>::ExitDisplayModeOnAccessKeyInvoked() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->get_ExitDisplayModeOnAccessKeyInvoked(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::ExitDisplayModeOnAccessKeyInvoked(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->put_ExitDisplayModeOnAccessKeyInvoked(value));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement4<D>::IsAccessKeyScope() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->get_IsAccessKeyScope(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::IsAccessKeyScope(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->put_IsAccessKeyScope(value));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyScopeOwner() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->get_AccessKeyScopeOwner(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyScopeOwner(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->put_AccessKeyScopeOwner(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IUIElement4<D>::AccessKey() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->get_AccessKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::AccessKey(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->put_AccessKey(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ContextRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->add_ContextRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested_revoker consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ContextRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ContextRequested_revoker>(this, ContextRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::ContextRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->remove_ContextRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::RoutedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->add_ContextCanceled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled_revoker consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::RoutedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ContextCanceled_revoker>(this, ContextCanceled(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::ContextCanceled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->remove_ContextCanceled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->add_AccessKeyDisplayRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyDisplayRequested_revoker>(this, AccessKeyDisplayRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->remove_AccessKeyDisplayRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->add_AccessKeyDisplayDismissed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyDisplayDismissed_revoker>(this, AccessKeyDisplayDismissed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->remove_AccessKeyDisplayDismissed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->add_AccessKeyInvoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked_revoker consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessKeyInvoked_revoker>(this, AccessKeyInvoked(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement4<D>::AccessKeyInvoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement4)->remove_AccessKeyInvoked(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Media::XamlLight> consume_Windows_UI_Xaml_IUIElement5<D>::Lights() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Media::XamlLight> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_Lights(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Input::KeyTipPlacementMode consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipPlacementMode() const
{
    Windows::UI::Xaml::Input::KeyTipPlacementMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_KeyTipPlacementMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_KeyTipPlacementMode(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipHorizontalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_KeyTipHorizontalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipHorizontalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_KeyTipHorizontalOffset(value));
}

template <typename D> double consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipVerticalOffset() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_KeyTipVerticalOffset(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::KeyTipVerticalOffset(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_KeyTipVerticalOffset(value));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusKeyboardNavigation() const
{
    Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_XYFocusKeyboardNavigation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusKeyboardNavigation(Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_XYFocusKeyboardNavigation(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusUpNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_XYFocusUpNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_XYFocusUpNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusDownNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_XYFocusDownNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_XYFocusDownNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusLeftNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_XYFocusLeftNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_XYFocusLeftNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::XYFocusNavigationStrategy consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusRightNavigationStrategy() const
{
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_XYFocusRightNavigationStrategy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_XYFocusRightNavigationStrategy(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::ElementHighContrastAdjustment consume_Windows_UI_Xaml_IUIElement5<D>::HighContrastAdjustment() const
{
    Windows::UI::Xaml::ElementHighContrastAdjustment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_HighContrastAdjustment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::HighContrastAdjustment(Windows::UI::Xaml::ElementHighContrastAdjustment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_HighContrastAdjustment(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::KeyboardNavigationMode consume_Windows_UI_Xaml_IUIElement5<D>::TabFocusNavigation() const
{
    Windows::UI::Xaml::Input::KeyboardNavigationMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->get_TabFocusNavigation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::TabFocusNavigation(Windows::UI::Xaml::Input::KeyboardNavigationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->put_TabFocusNavigation(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->add_GettingFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus_revoker consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::GettingFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GettingFocus_revoker>(this, GettingFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::GettingFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->remove_GettingFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->add_LosingFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus_revoker consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::LosingFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LosingFocus_revoker>(this, LosingFocus(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::LosingFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->remove_LosingFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->add_NoFocusCandidateFound(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound_revoker consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, NoFocusCandidateFound_revoker>(this, NoFocusCandidateFound(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::NoFocusCandidateFound(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->remove_NoFocusCandidateFound(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::StartBringIntoView() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->StartBringIntoView());
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement5<D>::StartBringIntoView(Windows::UI::Xaml::BringIntoViewOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement5)->StartBringIntoViewWithOptions(get_abi(options)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator> consume_Windows_UI_Xaml_IUIElement7<D>::KeyboardAccelerators() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->get_KeyboardAccelerators(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->add_CharacterReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived_revoker consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CharacterReceived_revoker>(this, CharacterReceived(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement7<D>::CharacterReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->remove_CharacterReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->add_ProcessKeyboardAccelerators(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators_revoker consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProcessKeyboardAccelerators_revoker>(this, ProcessKeyboardAccelerators(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement7<D>::ProcessKeyboardAccelerators(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->remove_ProcessKeyboardAccelerators(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->add_PreviewKeyDown(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown_revoker consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(auto_revoke_t, Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PreviewKeyDown_revoker>(this, PreviewKeyDown(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyDown(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->remove_PreviewKeyDown(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->add_PreviewKeyUp(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp_revoker consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(auto_revoke_t, Windows::UI::Xaml::Input::KeyEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PreviewKeyUp_revoker>(this, PreviewKeyUp(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement7<D>::PreviewKeyUp(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->remove_PreviewKeyUp(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement7<D>::TryInvokeKeyboardAccelerator(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement7)->TryInvokeKeyboardAccelerator(get_abi(args)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IUIElement8<D>::KeyTipTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->get_KeyTipTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement8<D>::KeyTipTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->put_KeyTipTarget(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyObject consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementTarget() const
{
    Windows::UI::Xaml::DependencyObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->get_KeyboardAcceleratorPlacementTarget(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementTarget(Windows::UI::Xaml::DependencyObject const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->put_KeyboardAcceleratorPlacementTarget(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementMode() const
{
    Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->get_KeyboardAcceleratorPlacementMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement8<D>::KeyboardAcceleratorPlacementMode(Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->put_KeyboardAcceleratorPlacementMode(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->add_BringIntoViewRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested_revoker consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BringIntoViewRequested_revoker>(this, BringIntoViewRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement8<D>::BringIntoViewRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IUIElement8)->remove_BringIntoViewRequested(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElement9<D>::CanBeScrollAnchor() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_CanBeScrollAnchor(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::CanBeScrollAnchor(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_CanBeScrollAnchor(value));
}

template <typename D> Windows::UI::Xaml::ScalarTransition consume_Windows_UI_Xaml_IUIElement9<D>::OpacityTransition() const
{
    Windows::UI::Xaml::ScalarTransition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_OpacityTransition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::OpacityTransition(Windows::UI::Xaml::ScalarTransition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_OpacityTransition(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_IUIElement9<D>::Translation() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_Translation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::Translation(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_Translation(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Vector3Transition consume_Windows_UI_Xaml_IUIElement9<D>::TranslationTransition() const
{
    Windows::UI::Xaml::Vector3Transition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_TranslationTransition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::TranslationTransition(Windows::UI::Xaml::Vector3Transition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_TranslationTransition(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Xaml_IUIElement9<D>::Rotation() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_Rotation(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::Rotation(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_Rotation(value));
}

template <typename D> Windows::UI::Xaml::ScalarTransition consume_Windows_UI_Xaml_IUIElement9<D>::RotationTransition() const
{
    Windows::UI::Xaml::ScalarTransition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_RotationTransition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::RotationTransition(Windows::UI::Xaml::ScalarTransition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_RotationTransition(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_IUIElement9<D>::Scale() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::Scale(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_Scale(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Vector3Transition consume_Windows_UI_Xaml_IUIElement9<D>::ScaleTransition() const
{
    Windows::UI::Xaml::Vector3Transition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_ScaleTransition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::ScaleTransition(Windows::UI::Xaml::Vector3Transition const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_ScaleTransition(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_UI_Xaml_IUIElement9<D>::TransformMatrix() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_TransformMatrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::TransformMatrix(Windows::Foundation::Numerics::float4x4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_TransformMatrix(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_IUIElement9<D>::CenterPoint() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_CenterPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::CenterPoint(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_CenterPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_IUIElement9<D>::RotationAxis() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->get_RotationAxis(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::RotationAxis(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->put_RotationAxis(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::StartAnimation(Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->StartAnimation(get_abi(animation)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElement9<D>::StopAnimation(Windows::UI::Composition::ICompositionAnimationBase const& animation) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElement9)->StopAnimation(get_abi(animation)));
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_IUIElementOverrides<D>::OnCreateAutomationPeer() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides)->OnCreateAutomationPeer(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementOverrides<D>::OnDisconnectVisualChildren() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides)->OnDisconnectVisualChildren());
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>> consume_Windows_UI_Xaml_IUIElementOverrides<D>::FindSubElementsForTouchTargeting(Windows::Foundation::Point const& point, Windows::Foundation::Rect const& boundingRect) const
{
    Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides)->FindSubElementsForTouchTargeting(get_abi(point), get_abi(boundingRect), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_IUIElementOverrides7<D>::GetChildrenInTabFocusOrder() const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides7)->GetChildrenInTabFocusOrder(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementOverrides7<D>::OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides7)->OnProcessKeyboardAccelerators(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementOverrides8<D>::OnKeyboardAcceleratorInvoked(Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides8)->OnKeyboardAcceleratorInvoked(get_abi(args)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementOverrides8<D>::OnBringIntoViewRequested(Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides8)->OnBringIntoViewRequested(get_abi(e)));
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementOverrides9<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementOverrides9)->PopulatePropertyInfoOverride(get_abi(propertyName), get_abi(animationPropertyInfo)));
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::KeyDownEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_KeyDownEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::KeyUpEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_KeyUpEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerEnteredEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerEnteredEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerPressedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerPressedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerMovedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerMovedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerReleasedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerReleasedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerExitedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerExitedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCaptureLostEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerCaptureLostEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCanceledEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerCanceledEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerWheelChangedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerWheelChangedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::TappedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_TappedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::DoubleTappedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_DoubleTappedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::HoldingEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_HoldingEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::RightTappedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_RightTappedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationStartingEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationStartingEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationInertiaStartingEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationInertiaStartingEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationStartedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationStartedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationDeltaEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationDeltaEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationCompletedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationCompletedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::DragEnterEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_DragEnterEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::DragLeaveEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_DragLeaveEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::DragOverEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_DragOverEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics<D>::DropEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_DropEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::AllowDropProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_AllowDropProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::OpacityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_OpacityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::ClipProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ClipProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::RenderTransformProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_RenderTransformProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::ProjectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ProjectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::RenderTransformOriginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_RenderTransformOriginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::IsHitTestVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_IsHitTestVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::VisibilityProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_VisibilityProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::UseLayoutRoundingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_UseLayoutRoundingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::TransitionsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_TransitionsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::CacheModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_CacheModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::IsTapEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_IsTapEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::IsDoubleTapEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_IsDoubleTapEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::IsRightTapEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_IsRightTapEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::IsHoldingEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_IsHoldingEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::ManipulationModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_ManipulationModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics<D>::PointerCapturesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics)->get_PointerCapturesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics10<D>::ShadowProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics10)->get_ShadowProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics2<D>::CompositeModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics2)->get_CompositeModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics3<D>::Transform3DProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics3)->get_Transform3DProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics3<D>::CanDragProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics3)->get_CanDragProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IUIElementStatics3<D>::TryStartDirectManipulation(Windows::UI::Xaml::Input::Pointer const& value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics3)->TryStartDirectManipulation(get_abi(value), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics4<D>::ContextFlyoutProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics4)->get_ContextFlyoutProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics4<D>::ExitDisplayModeOnAccessKeyInvokedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics4)->get_ExitDisplayModeOnAccessKeyInvokedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics4<D>::IsAccessKeyScopeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics4)->get_IsAccessKeyScopeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics4<D>::AccessKeyScopeOwnerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics4)->get_AccessKeyScopeOwnerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics4<D>::AccessKeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics4)->get_AccessKeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::LightsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_LightsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipPlacementModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipPlacementModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipHorizontalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipHorizontalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::KeyTipVerticalOffsetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_KeyTipVerticalOffsetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusKeyboardNavigationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusKeyboardNavigationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusUpNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusUpNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusDownNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusDownNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusLeftNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusLeftNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::XYFocusRightNavigationStrategyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_XYFocusRightNavigationStrategyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::HighContrastAdjustmentProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_HighContrastAdjustmentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics5<D>::TabFocusNavigationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics5)->get_TabFocusNavigationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics6<D>::GettingFocusEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics6)->get_GettingFocusEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics6<D>::LosingFocusEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics6)->get_LosingFocusEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics6<D>::NoFocusCandidateFoundEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics6)->get_NoFocusCandidateFoundEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics7<D>::PreviewKeyDownEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics7)->get_PreviewKeyDownEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics7<D>::CharacterReceivedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics7)->get_CharacterReceivedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics7<D>::PreviewKeyUpEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics7)->get_PreviewKeyUpEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics8<D>::BringIntoViewRequestedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->get_BringIntoViewRequestedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::RoutedEvent consume_Windows_UI_Xaml_IUIElementStatics8<D>::ContextRequestedEvent() const
{
    Windows::UI::Xaml::RoutedEvent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->get_ContextRequestedEvent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyTipTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->get_KeyTipTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyboardAcceleratorPlacementTargetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->get_KeyboardAcceleratorPlacementTargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics8<D>::KeyboardAcceleratorPlacementModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->get_KeyboardAcceleratorPlacementModeProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUIElementStatics8<D>::RegisterAsScrollPort(Windows::UI::Xaml::UIElement const& element) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics8)->RegisterAsScrollPort(get_abi(element)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IUIElementStatics9<D>::CanBeScrollAnchorProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementStatics9)->get_CanBeScrollAnchorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElementWeakCollection consume_Windows_UI_Xaml_IUIElementWeakCollectionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::UIElementWeakCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUIElementWeakCollectionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Exception() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Exception(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUnhandledExceptionEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IUnhandledExceptionEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IUnhandledExceptionEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_IVector3Transition<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVector3Transition)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVector3Transition<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVector3Transition)->put_Duration(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Vector3TransitionComponents consume_Windows_UI_Xaml_IVector3Transition<D>::Components() const
{
    Windows::UI::Xaml::Vector3TransitionComponents value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVector3Transition)->get_Components(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVector3Transition<D>::Components(Windows::UI::Xaml::Vector3TransitionComponents const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVector3Transition)->put_Components(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Vector3Transition consume_Windows_UI_Xaml_IVector3TransitionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Vector3Transition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVector3TransitionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_IVisualState<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualState)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Animation::Storyboard consume_Windows_UI_Xaml_IVisualState<D>::Storyboard() const
{
    Windows::UI::Xaml::Media::Animation::Storyboard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualState)->get_Storyboard(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualState<D>::Storyboard(Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualState)->put_Storyboard(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::SetterBaseCollection consume_Windows_UI_Xaml_IVisualState2<D>::Setters() const
{
    Windows::UI::Xaml::SetterBaseCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualState2)->get_Setters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::StateTriggerBase> consume_Windows_UI_Xaml_IVisualState2<D>::StateTriggers() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::StateTriggerBase> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualState2)->get_StateTriggers(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::VisualState consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::OldState() const
{
    Windows::UI::Xaml::VisualState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_OldState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::OldState(Windows::UI::Xaml::VisualState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_OldState(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::VisualState consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::NewState() const
{
    Windows::UI::Xaml::VisualState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_NewState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::NewState(Windows::UI::Xaml::VisualState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_NewState(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Control consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::Control() const
{
    Windows::UI::Xaml::Controls::Control value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->get_Control(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateChangedEventArgs<D>::Control(Windows::UI::Xaml::Controls::Control const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateChangedEventArgs)->put_Control(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IVisualStateGroup<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualTransition> consume_Windows_UI_Xaml_IVisualStateGroup<D>::Transitions() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualTransition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->get_Transitions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualState> consume_Windows_UI_Xaml_IVisualStateGroup<D>::States() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualState> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->get_States(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::VisualState consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentState() const
{
    Windows::UI::Xaml::VisualState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->get_CurrentState(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->add_CurrentStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged_revoker consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(auto_revoke_t, Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, CurrentStateChanged_revoker>(this, CurrentStateChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->remove_CurrentStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->add_CurrentStateChanging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging_revoker consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(auto_revoke_t, Windows::UI::Xaml::VisualStateChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, CurrentStateChanging_revoker>(this, CurrentStateChanging(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateGroup<D>::CurrentStateChanging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IVisualStateGroup)->remove_CurrentStateChanging(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::VisualStateManager consume_Windows_UI_Xaml_IVisualStateManagerFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::VisualStateManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IVisualStateManagerOverrides<D>::GoToStateCore(Windows::UI::Xaml::Controls::Control const& control, Windows::UI::Xaml::FrameworkElement const& templateRoot, param::hstring const& stateName, Windows::UI::Xaml::VisualStateGroup const& group, Windows::UI::Xaml::VisualState const& state, bool useTransitions) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerOverrides)->GoToStateCore(get_abi(control), get_abi(templateRoot), get_abi(stateName), get_abi(group), get_abi(state), useTransitions, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateManagerProtected<D>::RaiseCurrentStateChanging(Windows::UI::Xaml::VisualStateGroup const& stateGroup, Windows::UI::Xaml::VisualState const& oldState, Windows::UI::Xaml::VisualState const& newState, Windows::UI::Xaml::Controls::Control const& control) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerProtected)->RaiseCurrentStateChanging(get_abi(stateGroup), get_abi(oldState), get_abi(newState), get_abi(control)));
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateManagerProtected<D>::RaiseCurrentStateChanged(Windows::UI::Xaml::VisualStateGroup const& stateGroup, Windows::UI::Xaml::VisualState const& oldState, Windows::UI::Xaml::VisualState const& newState, Windows::UI::Xaml::Controls::Control const& control) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerProtected)->RaiseCurrentStateChanged(get_abi(stateGroup), get_abi(oldState), get_abi(newState), get_abi(control)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualStateGroup> consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GetVisualStateGroups(Windows::UI::Xaml::FrameworkElement const& obj) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualStateGroup> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerStatics)->GetVisualStateGroups(get_abi(obj), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::CustomVisualStateManagerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerStatics)->get_CustomVisualStateManagerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::VisualStateManager consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GetCustomVisualStateManager(Windows::UI::Xaml::FrameworkElement const& obj) const
{
    Windows::UI::Xaml::VisualStateManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerStatics)->GetCustomVisualStateManager(get_abi(obj), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::SetCustomVisualStateManager(Windows::UI::Xaml::FrameworkElement const& obj, Windows::UI::Xaml::VisualStateManager const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerStatics)->SetCustomVisualStateManager(get_abi(obj), get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_IVisualStateManagerStatics<D>::GoToState(Windows::UI::Xaml::Controls::Control const& control, param::hstring const& stateName, bool useTransitions) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualStateManagerStatics)->GoToState(get_abi(control), get_abi(stateName), useTransitions, &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Duration consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedDuration() const
{
    Windows::UI::Xaml::Duration value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->get_GeneratedDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedDuration(Windows::UI::Xaml::Duration const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->put_GeneratedDuration(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::EasingFunctionBase consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedEasingFunction() const
{
    Windows::UI::Xaml::Media::Animation::EasingFunctionBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->get_GeneratedEasingFunction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualTransition<D>::GeneratedEasingFunction(Windows::UI::Xaml::Media::Animation::EasingFunctionBase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->put_GeneratedEasingFunction(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IVisualTransition<D>::To() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->get_To(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualTransition<D>::To(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->put_To(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_IVisualTransition<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->get_From(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualTransition<D>::From(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->put_From(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Media::Animation::Storyboard consume_Windows_UI_Xaml_IVisualTransition<D>::Storyboard() const
{
    Windows::UI::Xaml::Media::Animation::Storyboard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->get_Storyboard(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IVisualTransition<D>::Storyboard(Windows::UI::Xaml::Media::Animation::Storyboard const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransition)->put_Storyboard(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::VisualTransition consume_Windows_UI_Xaml_IVisualTransitionFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::VisualTransition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IVisualTransitionFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_IWindow<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IWindow<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->get_Visible(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IWindow<D>::Content() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::Content(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->put_Content(get_abi(value)));
}

template <typename D> Windows::UI::Core::CoreWindow consume_Windows_UI_Xaml_IWindow<D>::CoreWindow() const
{
    Windows::UI::Core::CoreWindow value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->get_CoreWindow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Xaml_IWindow<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IWindow<D>::Activated(Windows::UI::Xaml::WindowActivatedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->add_Activated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::Activated_revoker consume_Windows_UI_Xaml_IWindow<D>::Activated(auto_revoke_t, Windows::UI::Xaml::WindowActivatedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Activated_revoker>(this, Activated(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::Activated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IWindow)->remove_Activated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IWindow<D>::Closed(Windows::UI::Xaml::WindowClosedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::Closed_revoker consume_Windows_UI_Xaml_IWindow<D>::Closed(auto_revoke_t, Windows::UI::Xaml::WindowClosedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IWindow)->remove_Closed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(Windows::UI::Xaml::WindowSizeChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->add_SizeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::SizeChanged_revoker consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(auto_revoke_t, Windows::UI::Xaml::WindowSizeChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, SizeChanged_revoker>(this, SizeChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::SizeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IWindow)->remove_SizeChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(Windows::UI::Xaml::WindowVisibilityChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->add_VisibilityChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged_revoker consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(auto_revoke_t, Windows::UI::Xaml::WindowVisibilityChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::VisibilityChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IWindow)->remove_VisibilityChanged(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::Activate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->Activate());
}

template <typename D> void consume_Windows_UI_Xaml_IWindow<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow)->Close());
}

template <typename D> void consume_Windows_UI_Xaml_IWindow2<D>::SetTitleBar(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow2)->SetTitleBar(get_abi(value)));
}

template <typename D> Windows::UI::Composition::Compositor consume_Windows_UI_Xaml_IWindow3<D>::Compositor() const
{
    Windows::UI::Composition::Compositor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow3)->get_Compositor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_Xaml_IWindow4<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindow4)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Window consume_Windows_UI_Xaml_IWindowCreatedEventArgs<D>::Window() const
{
    Windows::UI::Xaml::Window value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindowCreatedEventArgs)->get_Window(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Window consume_Windows_UI_Xaml_IWindowStatics<D>::Current() const
{
    Windows::UI::Xaml::Window value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IWindowStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_IXamlRoot<D>::Content() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Size consume_Windows_UI_Xaml_IXamlRoot<D>::Size() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->get_Size(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_IXamlRoot<D>::RasterizationScale() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->get_RasterizationScale(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_IXamlRoot<D>::IsHostVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->get_IsHostVisible(&value));
    return value;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_Xaml_IXamlRoot<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::XamlRoot, Windows::UI::Xaml::XamlRootChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_IXamlRoot<D>::Changed_revoker consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::XamlRoot, Windows::UI::Xaml::XamlRootChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_IXamlRoot<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::IXamlRoot)->remove_Changed(get_abi(token)));
}

template <> struct delegate<Windows::UI::Xaml::ApplicationInitializationCallback>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::ApplicationInitializationCallback, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::ApplicationInitializationCallback, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* p) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::Xaml::ApplicationInitializationCallbackParams const*>(&p));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::BindingFailedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::BindingFailedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::BindingFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::BindingFailedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::CreateDefaultValueCallback>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::CreateDefaultValueCallback, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::CreateDefaultValueCallback, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void** result) noexcept final
        {
            try
            {
                *result = detach_from<Windows::Foundation::IInspectable>((*this)());
                return 0;
            }
            catch (...)
            {
            *result = nullptr;
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::DependencyPropertyChangedCallback>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::DependencyPropertyChangedCallback, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::DependencyPropertyChangedCallback, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* dp) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::DependencyPropertyChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::DependencyPropertyChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::DependencyPropertyChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::DependencyPropertyChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::DragEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::DragEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::DragEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::DragEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::EnteredBackgroundEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::EnteredBackgroundEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::EnteredBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::EnteredBackgroundEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::ExceptionRoutedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::ExceptionRoutedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::ExceptionRoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::ExceptionRoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::LeavingBackgroundEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::LeavingBackgroundEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::LeavingBackgroundEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::LeavingBackgroundEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::PropertyChangedCallback>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::PropertyChangedCallback, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::PropertyChangedCallback, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* d, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&d), *reinterpret_cast<Windows::UI::Xaml::DependencyPropertyChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::RoutedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::RoutedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::RoutedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::RoutedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::SizeChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::SizeChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::SizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::SizeChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::SuspendingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::SuspendingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::SuspendingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::ApplicationModel::SuspendingEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::UnhandledExceptionEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::UnhandledExceptionEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::UnhandledExceptionEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::UnhandledExceptionEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::VisualStateChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::VisualStateChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::VisualStateChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::VisualStateChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::WindowActivatedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::WindowActivatedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::WindowActivatedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Core::WindowActivatedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::WindowClosedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::WindowClosedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::WindowClosedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Core::CoreWindowEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::WindowSizeChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::WindowSizeChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::WindowSizeChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Core::WindowSizeChangedEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::WindowVisibilityChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::WindowVisibilityChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::WindowVisibilityChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Core::VisibilityChangedEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::IAdaptiveTrigger> : produce_base<D, Windows::UI::Xaml::IAdaptiveTrigger>
{
    int32_t WINRT_CALL get_MinWindowWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinWindowWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinWindowWidth(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowWidth, WINRT_WRAP(void), double);
            this->shim().MinWindowWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinWindowHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinWindowHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinWindowHeight(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowHeight, WINRT_WRAP(void), double);
            this->shim().MinWindowHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IAdaptiveTriggerFactory> : produce_base<D, Windows::UI::Xaml::IAdaptiveTriggerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::AdaptiveTrigger), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::AdaptiveTrigger>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IAdaptiveTriggerStatics> : produce_base<D, Windows::UI::Xaml::IAdaptiveTriggerStatics>
{
    int32_t WINRT_CALL get_MinWindowWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinWindowWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinWindowHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWindowHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinWindowHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplication> : produce_base<D, Windows::UI::Xaml::IApplication>
{
    int32_t WINRT_CALL get_Resources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resources, WINRT_WRAP(Windows::UI::Xaml::ResourceDictionary));
            *value = detach_from<Windows::UI::Xaml::ResourceDictionary>(this->shim().Resources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Resources(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resources, WINRT_WRAP(void), Windows::UI::Xaml::ResourceDictionary const&);
            this->shim().Resources(*reinterpret_cast<Windows::UI::Xaml::ResourceDictionary const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DebugSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DebugSettings, WINRT_WRAP(Windows::UI::Xaml::DebugSettings));
            *value = detach_from<Windows::UI::Xaml::DebugSettings>(this->shim().DebugSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedTheme(Windows::UI::Xaml::ApplicationTheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedTheme, WINRT_WRAP(Windows::UI::Xaml::ApplicationTheme));
            *value = detach_from<Windows::UI::Xaml::ApplicationTheme>(this->shim().RequestedTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestedTheme(Windows::UI::Xaml::ApplicationTheme value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedTheme, WINRT_WRAP(void), Windows::UI::Xaml::ApplicationTheme const&);
            this->shim().RequestedTheme(*reinterpret_cast<Windows::UI::Xaml::ApplicationTheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UnhandledException(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnhandledException, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::UnhandledExceptionEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().UnhandledException(*reinterpret_cast<Windows::UI::Xaml::UnhandledExceptionEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UnhandledException(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UnhandledException, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UnhandledException(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Suspending(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suspending, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::SuspendingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Suspending(*reinterpret_cast<Windows::UI::Xaml::SuspendingEventHandler const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplication2> : produce_base<D, Windows::UI::Xaml::IApplication2>
{
    int32_t WINRT_CALL get_FocusVisualKind(Windows::UI::Xaml::FocusVisualKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualKind, WINRT_WRAP(Windows::UI::Xaml::FocusVisualKind));
            *value = detach_from<Windows::UI::Xaml::FocusVisualKind>(this->shim().FocusVisualKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualKind(Windows::UI::Xaml::FocusVisualKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualKind, WINRT_WRAP(void), Windows::UI::Xaml::FocusVisualKind const&);
            this->shim().FocusVisualKind(*reinterpret_cast<Windows::UI::Xaml::FocusVisualKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequiresPointerMode(Windows::UI::Xaml::ApplicationRequiresPointerMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiresPointerMode, WINRT_WRAP(Windows::UI::Xaml::ApplicationRequiresPointerMode));
            *value = detach_from<Windows::UI::Xaml::ApplicationRequiresPointerMode>(this->shim().RequiresPointerMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequiresPointerMode(Windows::UI::Xaml::ApplicationRequiresPointerMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiresPointerMode, WINRT_WRAP(void), Windows::UI::Xaml::ApplicationRequiresPointerMode const&);
            this->shim().RequiresPointerMode(*reinterpret_cast<Windows::UI::Xaml::ApplicationRequiresPointerMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LeavingBackground(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeavingBackground, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::LeavingBackgroundEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LeavingBackground(*reinterpret_cast<Windows::UI::Xaml::LeavingBackgroundEventHandler const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(EnteredBackground, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::EnteredBackgroundEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().EnteredBackground(*reinterpret_cast<Windows::UI::Xaml::EnteredBackgroundEventHandler const*>(&handler)));
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplication3> : produce_base<D, Windows::UI::Xaml::IApplication3>
{
    int32_t WINRT_CALL get_HighContrastAdjustment(Windows::UI::Xaml::ApplicationHighContrastAdjustment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(Windows::UI::Xaml::ApplicationHighContrastAdjustment));
            *value = detach_from<Windows::UI::Xaml::ApplicationHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HighContrastAdjustment(Windows::UI::Xaml::ApplicationHighContrastAdjustment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(void), Windows::UI::Xaml::ApplicationHighContrastAdjustment const&);
            this->shim().HighContrastAdjustment(*reinterpret_cast<Windows::UI::Xaml::ApplicationHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplicationFactory> : produce_base<D, Windows::UI::Xaml::IApplicationFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Application), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Application>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplicationInitializationCallbackParams> : produce_base<D, Windows::UI::Xaml::IApplicationInitializationCallbackParams>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplicationOverrides> : produce_base<D, Windows::UI::Xaml::IApplicationOverrides>
{
    int32_t WINRT_CALL OnActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::IActivatedEventArgs const&);
            this->shim().OnActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::IActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnLaunched(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnLaunched, WINRT_WRAP(void), Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const&);
            this->shim().OnLaunched(*reinterpret_cast<Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnFileActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnFileActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::FileActivatedEventArgs const&);
            this->shim().OnFileActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::FileActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnSearchActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnSearchActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::SearchActivatedEventArgs const&);
            this->shim().OnSearchActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::SearchActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnShareTargetActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnShareTargetActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const&);
            this->shim().OnShareTargetActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnFileOpenPickerActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnFileOpenPickerActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const&);
            this->shim().OnFileOpenPickerActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnFileSavePickerActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnFileSavePickerActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const&);
            this->shim().OnFileSavePickerActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnCachedFileUpdaterActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnCachedFileUpdaterActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const&);
            this->shim().OnCachedFileUpdaterActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnWindowCreated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnWindowCreated, WINRT_WRAP(void), Windows::UI::Xaml::WindowCreatedEventArgs const&);
            this->shim().OnWindowCreated(*reinterpret_cast<Windows::UI::Xaml::WindowCreatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplicationOverrides2> : produce_base<D, Windows::UI::Xaml::IApplicationOverrides2>
{
    int32_t WINRT_CALL OnBackgroundActivated(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnBackgroundActivated, WINRT_WRAP(void), Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const&);
            this->shim().OnBackgroundActivated(*reinterpret_cast<Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IApplicationStatics> : produce_base<D, Windows::UI::Xaml::IApplicationStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::UI::Xaml::Application));
            *value = detach_from<Windows::UI::Xaml::Application>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start(void* callback) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void), Windows::UI::Xaml::ApplicationInitializationCallback const&);
            this->shim().Start(*reinterpret_cast<Windows::UI::Xaml::ApplicationInitializationCallback const*>(&callback));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadComponent(void* component, void* resourceLocator) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadComponent, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::Uri const&);
            this->shim().LoadComponent(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&component), *reinterpret_cast<Windows::Foundation::Uri const*>(&resourceLocator));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadComponentWithResourceLocation(void* component, void* resourceLocator, Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation componentResourceLocation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadComponent, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::Uri const&, Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const&);
            this->shim().LoadComponent(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&component), *reinterpret_cast<Windows::Foundation::Uri const*>(&resourceLocator), *reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const*>(&componentResourceLocation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IBindingFailedEventArgs> : produce_base<D, Windows::UI::Xaml::IBindingFailedEventArgs>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IBringIntoViewOptions> : produce_base<D, Windows::UI::Xaml::IBringIntoViewOptions>
{
    int32_t WINRT_CALL get_AnimationDesired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationDesired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AnimationDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnimationDesired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationDesired, WINRT_WRAP(void), bool);
            this->shim().AnimationDesired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetRect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetRect, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Rect>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Rect>>(this->shim().TargetRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetRect(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetRect, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Rect> const&);
            this->shim().TargetRect(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IBringIntoViewOptions2> : produce_base<D, Windows::UI::Xaml::IBringIntoViewOptions2>
{
    int32_t WINRT_CALL get_HorizontalAlignmentRatio(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalAlignmentRatio(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(void), double);
            this->shim().HorizontalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalAlignmentRatio(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalAlignmentRatio(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(void), double);
            this->shim().VerticalAlignmentRatio(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(void), double);
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(void), double);
            this->shim().VerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IBringIntoViewRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::IBringIntoViewRequestedEventArgs>
{
    int32_t WINRT_CALL get_TargetElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetElement, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().TargetElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetElement(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetElement, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().TargetElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnimationDesired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationDesired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AnimationDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AnimationDesired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationDesired, WINRT_WRAP(void), bool);
            this->shim().AnimationDesired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().TargetRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetRect(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetRect, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().TargetRect(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalAlignmentRatio(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentRatio, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalAlignmentRatio(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentRatio, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalAlignmentRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalOffset, WINRT_WRAP(void), double);
            this->shim().HorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().VerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalOffset, WINRT_WRAP(void), double);
            this->shim().VerticalOffset(value);
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
struct produce<D, Windows::UI::Xaml::IBrushTransition> : produce_base<D, Windows::UI::Xaml::IBrushTransition>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IBrushTransitionFactory> : produce_base<D, Windows::UI::Xaml::IBrushTransitionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::BrushTransition), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::BrushTransition>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IColorPaletteResources> : produce_base<D, Windows::UI::Xaml::IColorPaletteResources>
{
    int32_t WINRT_CALL get_AltHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().AltHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AltHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().AltHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().AltLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AltLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().AltLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltMedium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMedium, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().AltMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AltMedium(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMedium, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().AltMedium(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltMediumHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMediumHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().AltMediumHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AltMediumHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMediumHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().AltMediumHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltMediumLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMediumLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().AltMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AltMediumLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltMediumLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().AltMediumLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BaseHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BaseHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BaseLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BaseLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseMedium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMedium, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BaseMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseMedium(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMedium, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BaseMedium(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseMediumHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMediumHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BaseMediumHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseMediumHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMediumHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BaseMediumHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseMediumLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMediumLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().BaseMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseMediumLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMediumLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().BaseMediumLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeAltLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeAltLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeAltLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeAltLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeAltLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeAltLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeBlackHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeBlackHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeBlackHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeBlackHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeBlackLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeBlackLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeBlackLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeBlackLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeBlackMediumLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackMediumLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeBlackMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeBlackMediumLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackMediumLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeBlackMediumLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeBlackMedium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackMedium, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeBlackMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeBlackMedium(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeBlackMedium, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeBlackMedium(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeDisabledHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeDisabledHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeDisabledHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeDisabledHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeDisabledHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeDisabledHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeDisabledLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeDisabledLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeDisabledLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeDisabledLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeDisabledLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeDisabledLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeHigh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeHigh, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeHigh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeHigh, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeHigh(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeMedium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeMedium, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeMedium(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeMedium, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeMedium(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeMediumLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeMediumLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeMediumLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeMediumLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeMediumLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeMediumLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeWhite(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeWhite, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeWhite(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeWhite, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeWhite(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChromeGray(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeGray, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ChromeGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChromeGray(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChromeGray, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ChromeGray(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListLow, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ListLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListLow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListLow, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ListLow(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListMedium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListMedium, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ListMedium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListMedium(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListMedium, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ListMedium(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorText, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().ErrorText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ErrorText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorText, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().ErrorText(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Accent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accent, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().Accent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Accent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accent, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::UI::Color> const&);
            this->shim().Accent(*reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Color> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IColorPaletteResourcesFactory> : produce_base<D, Windows::UI::Xaml::IColorPaletteResourcesFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::ColorPaletteResources), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::ColorPaletteResources>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ICornerRadiusHelper> : produce_base<D, Windows::UI::Xaml::ICornerRadiusHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ICornerRadiusHelperStatics> : produce_base<D, Windows::UI::Xaml::ICornerRadiusHelperStatics>
{
    int32_t WINRT_CALL FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft, struct struct_Windows_UI_Xaml_CornerRadius* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromRadii, WINRT_WRAP(Windows::UI::Xaml::CornerRadius), double, double, double, double);
            *result = detach_from<Windows::UI::Xaml::CornerRadius>(this->shim().FromRadii(topLeft, topRight, bottomRight, bottomLeft));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromUniformRadius(double uniformRadius, struct struct_Windows_UI_Xaml_CornerRadius* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromUniformRadius, WINRT_WRAP(Windows::UI::Xaml::CornerRadius), double);
            *result = detach_from<Windows::UI::Xaml::CornerRadius>(this->shim().FromUniformRadius(uniformRadius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataContextChangedEventArgs> : produce_base<D, Windows::UI::Xaml::IDataContextChangedEventArgs>
{
    int32_t WINRT_CALL get_NewValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().NewValue());
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
struct produce<D, Windows::UI::Xaml::IDataTemplate> : produce_base<D, Windows::UI::Xaml::IDataTemplate>
{
    int32_t WINRT_CALL LoadContent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadContent, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *result = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().LoadContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataTemplateExtension> : produce_base<D, Windows::UI::Xaml::IDataTemplateExtension>
{
    int32_t WINRT_CALL ResetTemplate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetTemplate, WINRT_WRAP(void));
            this->shim().ResetTemplate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessBinding(uint32_t phase, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessBinding, WINRT_WRAP(bool), uint32_t);
            *result = detach_from<bool>(this->shim().ProcessBinding(phase));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProcessBindings(void* arg, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessBindings, WINRT_WRAP(int32_t), Windows::UI::Xaml::Controls::ContainerContentChangingEventArgs const&);
            *result = detach_from<int32_t>(this->shim().ProcessBindings(*reinterpret_cast<Windows::UI::Xaml::Controls::ContainerContentChangingEventArgs const*>(&arg)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataTemplateFactory> : produce_base<D, Windows::UI::Xaml::IDataTemplateFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::DataTemplate), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DataTemplate>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataTemplateKey> : produce_base<D, Windows::UI::Xaml::IDataTemplateKey>
{
    int32_t WINRT_CALL get_DataType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataType, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().DataType(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataTemplateKeyFactory> : produce_base<D, Windows::UI::Xaml::IDataTemplateKeyFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::DataTemplateKey), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DataTemplateKey>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithType(void* dataType, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithType, WINRT_WRAP(Windows::UI::Xaml::DataTemplateKey), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DataTemplateKey>(this->shim().CreateInstanceWithType(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&dataType), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDataTemplateStatics2> : produce_base<D, Windows::UI::Xaml::IDataTemplateStatics2>
{
    int32_t WINRT_CALL get_ExtensionInstanceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtensionInstanceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExtensionInstanceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetExtensionInstance(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetExtensionInstance, WINRT_WRAP(Windows::UI::Xaml::IDataTemplateExtension), Windows::UI::Xaml::FrameworkElement const&);
            *result = detach_from<Windows::UI::Xaml::IDataTemplateExtension>(this->shim().GetExtensionInstance(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetExtensionInstance(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetExtensionInstance, WINRT_WRAP(void), Windows::UI::Xaml::FrameworkElement const&, Windows::UI::Xaml::IDataTemplateExtension const&);
            this->shim().SetExtensionInstance(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&element), *reinterpret_cast<Windows::UI::Xaml::IDataTemplateExtension const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDebugSettings> : produce_base<D, Windows::UI::Xaml::IDebugSettings>
{
    int32_t WINRT_CALL get_EnableFrameRateCounter(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableFrameRateCounter, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableFrameRateCounter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableFrameRateCounter(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableFrameRateCounter, WINRT_WRAP(void), bool);
            this->shim().EnableFrameRateCounter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBindingTracingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBindingTracingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBindingTracingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsBindingTracingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBindingTracingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsBindingTracingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverdrawHeatMapEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverdrawHeatMapEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverdrawHeatMapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOverdrawHeatMapEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverdrawHeatMapEnabled, WINRT_WRAP(void), bool);
            this->shim().IsOverdrawHeatMapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BindingFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BindingFailed, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::BindingFailedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().BindingFailed(*reinterpret_cast<Windows::UI::Xaml::BindingFailedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BindingFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BindingFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BindingFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDebugSettings2> : produce_base<D, Windows::UI::Xaml::IDebugSettings2>
{
    int32_t WINRT_CALL get_EnableRedrawRegions(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableRedrawRegions, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EnableRedrawRegions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EnableRedrawRegions(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableRedrawRegions, WINRT_WRAP(void), bool);
            this->shim().EnableRedrawRegions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDebugSettings3> : produce_base<D, Windows::UI::Xaml::IDebugSettings3>
{
    int32_t WINRT_CALL get_IsTextPerformanceVisualizationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTextPerformanceVisualizationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTextPerformanceVisualizationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTextPerformanceVisualizationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTextPerformanceVisualizationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsTextPerformanceVisualizationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDebugSettings4> : produce_base<D, Windows::UI::Xaml::IDebugSettings4>
{
    int32_t WINRT_CALL get_FailFastOnErrors(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailFastOnErrors, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().FailFastOnErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FailFastOnErrors(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailFastOnErrors, WINRT_WRAP(void), bool);
            this->shim().FailFastOnErrors(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyObject> : produce_base<D, Windows::UI::Xaml::IDependencyObject>
{
    int32_t WINRT_CALL GetValue(void* dp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::DependencyProperty const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValue(void* dp, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValue, WINRT_WRAP(void), Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::IInspectable const&);
            this->shim().SetValue(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearValue(void* dp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearValue, WINRT_WRAP(void), Windows::UI::Xaml::DependencyProperty const&);
            this->shim().ClearValue(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadLocalValue(void* dp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadLocalValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::DependencyProperty const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ReadLocalValue(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnimationBaseValue(void* dp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnimationBaseValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::DependencyProperty const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetAnimationBaseValue(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::UI::Xaml::IDependencyObject2> : produce_base<D, Windows::UI::Xaml::IDependencyObject2>
{
    int32_t WINRT_CALL RegisterPropertyChangedCallback(void* dp, void* callback, int64_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterPropertyChangedCallback, WINRT_WRAP(int64_t), Windows::UI::Xaml::DependencyProperty const&, Windows::UI::Xaml::DependencyPropertyChangedCallback const&);
            *result = detach_from<int64_t>(this->shim().RegisterPropertyChangedCallback(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<Windows::UI::Xaml::DependencyPropertyChangedCallback const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterPropertyChangedCallback(void* dp, int64_t token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterPropertyChangedCallback, WINRT_WRAP(void), Windows::UI::Xaml::DependencyProperty const&, int64_t);
            this->shim().UnregisterPropertyChangedCallback(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp), token);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyObjectCollectionFactory> : produce_base<D, Windows::UI::Xaml::IDependencyObjectCollectionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::DependencyObjectCollection), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DependencyObjectCollection>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyObjectFactory> : produce_base<D, Windows::UI::Xaml::IDependencyObjectFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::DependencyObject), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyProperty> : produce_base<D, Windows::UI::Xaml::IDependencyProperty>
{
    int32_t WINRT_CALL GetMetadata(struct struct_Windows_UI_Xaml_Interop_TypeName forType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMetadata, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::UI::Xaml::Interop::TypeName const&);
            *result = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().GetMetadata(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&forType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyPropertyChangedEventArgs> : produce_base<D, Windows::UI::Xaml::IDependencyPropertyChangedEventArgs>
{
    int32_t WINRT_CALL get_Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().OldValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().NewValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDependencyPropertyStatics> : produce_base<D, Windows::UI::Xaml::IDependencyPropertyStatics>
{
    int32_t WINRT_CALL get_UnsetValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnsetValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().UnsetValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Register(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName propertyType, struct struct_Windows_UI_Xaml_Interop_TypeName ownerType, void* typeMetadata, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty), hstring const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::UI::Xaml::PropertyMetadata const&);
            *result = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Register(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&propertyType), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&ownerType), *reinterpret_cast<Windows::UI::Xaml::PropertyMetadata const*>(&typeMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAttached(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName propertyType, struct struct_Windows_UI_Xaml_Interop_TypeName ownerType, void* defaultMetadata, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAttached, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty), hstring const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::UI::Xaml::PropertyMetadata const&);
            *result = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RegisterAttached(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&propertyType), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&ownerType), *reinterpret_cast<Windows::UI::Xaml::PropertyMetadata const*>(&defaultMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDispatcherTimer> : produce_base<D, Windows::UI::Xaml::IDispatcherTimer>
{
    int32_t WINRT_CALL get_Interval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Interval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Interval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL add_Tick(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tick, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Tick(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Tick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Tick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Tick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDispatcherTimerFactory> : produce_base<D, Windows::UI::Xaml::IDispatcherTimerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::DispatcherTimer), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::DispatcherTimer>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragEventArgs> : produce_base<D, Windows::UI::Xaml::IDragEventArgs>
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

    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackage));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackage const&);
            this->shim().Data(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragEventArgs2> : produce_base<D, Windows::UI::Xaml::IDragEventArgs2>
{
    int32_t WINRT_CALL get_DataView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataView, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageView));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageView>(this->shim().DataView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragUIOverride(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragUIOverride, WINRT_WRAP(Windows::UI::Xaml::DragUIOverride));
            *value = detach_from<Windows::UI::Xaml::DragUIOverride>(this->shim().DragUIOverride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Modifiers(Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Modifiers, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DragDrop::DragDropModifiers>(this->shim().Modifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcceptedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptedOperation, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AcceptedOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AcceptedOperation(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptedOperation, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackageOperation const&);
            this->shim().AcceptedOperation(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::Xaml::DragOperationDeferral));
            *result = detach_from<Windows::UI::Xaml::DragOperationDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragEventArgs3> : produce_base<D, Windows::UI::Xaml::IDragEventArgs3>
{
    int32_t WINRT_CALL get_AllowedOperations(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedOperations, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AllowedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragOperationDeferral> : produce_base<D, Windows::UI::Xaml::IDragOperationDeferral>
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
struct produce<D, Windows::UI::Xaml::IDragStartingEventArgs> : produce_base<D, Windows::UI::Xaml::IDragStartingEventArgs>
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

    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackage));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackage>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragUI(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragUI, WINRT_WRAP(Windows::UI::Xaml::DragUI));
            *value = detach_from<Windows::UI::Xaml::DragUI>(this->shim().DragUI());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::Xaml::DragOperationDeferral));
            *result = detach_from<Windows::UI::Xaml::DragOperationDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPosition(void* relativeTo, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPosition, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetPosition(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&relativeTo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragStartingEventArgs2> : produce_base<D, Windows::UI::Xaml::IDragStartingEventArgs2>
{
    int32_t WINRT_CALL get_AllowedOperations(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedOperations, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().AllowedOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowedOperations(Windows::ApplicationModel::DataTransfer::DataPackageOperation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedOperations, WINRT_WRAP(void), Windows::ApplicationModel::DataTransfer::DataPackageOperation const&);
            this->shim().AllowedOperations(*reinterpret_cast<Windows::ApplicationModel::DataTransfer::DataPackageOperation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragUI> : produce_base<D, Windows::UI::Xaml::IDragUI>
{
    int32_t WINRT_CALL SetContentFromBitmapImage(void* bitmapImage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromBitmapImage, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::BitmapImage const&);
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromBitmapImageWithAnchorPoint(void* bitmapImage, Windows::Foundation::Point anchorPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromBitmapImage, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::BitmapImage const&, Windows::Foundation::Point const&);
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage), *reinterpret_cast<Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromSoftwareBitmap(void* softwareBitmap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromSoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromSoftwareBitmapWithAnchorPoint(void* softwareBitmap, Windows::Foundation::Point anchorPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromSoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&, Windows::Foundation::Point const&);
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap), *reinterpret_cast<Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromDataPackage() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromDataPackage, WINRT_WRAP(void));
            this->shim().SetContentFromDataPackage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDragUIOverride> : produce_base<D, Windows::UI::Xaml::IDragUIOverride>
{
    int32_t WINRT_CALL get_Caption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Caption(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(void), hstring const&);
            this->shim().Caption(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsContentVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsContentVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsContentVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentVisible, WINRT_WRAP(void), bool);
            this->shim().IsContentVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCaptionVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCaptionVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCaptionVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCaptionVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCaptionVisible, WINRT_WRAP(void), bool);
            this->shim().IsCaptionVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGlyphVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGlyphVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGlyphVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsGlyphVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGlyphVisible, WINRT_WRAP(void), bool);
            this->shim().IsGlyphVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromBitmapImage(void* bitmapImage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromBitmapImage, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::BitmapImage const&);
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromBitmapImageWithAnchorPoint(void* bitmapImage, Windows::Foundation::Point anchorPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromBitmapImage, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::BitmapImage const&, Windows::Foundation::Point const&);
            this->shim().SetContentFromBitmapImage(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::BitmapImage const*>(&bitmapImage), *reinterpret_cast<Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromSoftwareBitmap(void* softwareBitmap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromSoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetContentFromSoftwareBitmapWithAnchorPoint(void* softwareBitmap, Windows::Foundation::Point anchorPoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetContentFromSoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&, Windows::Foundation::Point const&);
            this->shim().SetContentFromSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap), *reinterpret_cast<Windows::Foundation::Point const*>(&anchorPoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDropCompletedEventArgs> : produce_base<D, Windows::UI::Xaml::IDropCompletedEventArgs>
{
    int32_t WINRT_CALL get_DropResult(Windows::ApplicationModel::DataTransfer::DataPackageOperation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropResult, WINRT_WRAP(Windows::ApplicationModel::DataTransfer::DataPackageOperation));
            *value = detach_from<Windows::ApplicationModel::DataTransfer::DataPackageOperation>(this->shim().DropResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDurationHelper> : produce_base<D, Windows::UI::Xaml::IDurationHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IDurationHelperStatics> : produce_base<D, Windows::UI::Xaml::IDurationHelperStatics>
{
    int32_t WINRT_CALL get_Automatic(struct struct_Windows_UI_Xaml_Duration* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Automatic, WINRT_WRAP(Windows::UI::Xaml::Duration));
            *value = detach_from<Windows::UI::Xaml::Duration>(this->shim().Automatic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Forever(struct struct_Windows_UI_Xaml_Duration* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Forever, WINRT_WRAP(Windows::UI::Xaml::Duration));
            *value = detach_from<Windows::UI::Xaml::Duration>(this->shim().Forever());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Compare(struct struct_Windows_UI_Xaml_Duration duration1, struct struct_Windows_UI_Xaml_Duration duration2, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compare, WINRT_WRAP(int32_t), Windows::UI::Xaml::Duration const&, Windows::UI::Xaml::Duration const&);
            *result = detach_from<int32_t>(this->shim().Compare(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&duration1), *reinterpret_cast<Windows::UI::Xaml::Duration const*>(&duration2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromTimeSpan(Windows::Foundation::TimeSpan timeSpan, struct struct_Windows_UI_Xaml_Duration* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromTimeSpan, WINRT_WRAP(Windows::UI::Xaml::Duration), Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::UI::Xaml::Duration>(this->shim().FromTimeSpan(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeSpan)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHasTimeSpan(struct struct_Windows_UI_Xaml_Duration target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHasTimeSpan, WINRT_WRAP(bool), Windows::UI::Xaml::Duration const&);
            *result = detach_from<bool>(this->shim().GetHasTimeSpan(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Add(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration duration, struct struct_Windows_UI_Xaml_Duration* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(Windows::UI::Xaml::Duration), Windows::UI::Xaml::Duration const&, Windows::UI::Xaml::Duration const&);
            *result = detach_from<Windows::UI::Xaml::Duration>(this->shim().Add(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<Windows::UI::Xaml::Duration const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::UI::Xaml::Duration const&, Windows::UI::Xaml::Duration const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<Windows::UI::Xaml::Duration const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Subtract(struct struct_Windows_UI_Xaml_Duration target, struct struct_Windows_UI_Xaml_Duration duration, struct struct_Windows_UI_Xaml_Duration* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtract, WINRT_WRAP(Windows::UI::Xaml::Duration), Windows::UI::Xaml::Duration const&, Windows::UI::Xaml::Duration const&);
            *result = detach_from<Windows::UI::Xaml::Duration>(this->shim().Subtract(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&target), *reinterpret_cast<Windows::UI::Xaml::Duration const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IEffectiveViewportChangedEventArgs> : produce_base<D, Windows::UI::Xaml::IEffectiveViewportChangedEventArgs>
{
    int32_t WINRT_CALL get_EffectiveViewport(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectiveViewport, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().EffectiveViewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxViewport(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxViewport, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().MaxViewport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BringIntoViewDistanceX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BringIntoViewDistanceX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BringIntoViewDistanceX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BringIntoViewDistanceY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BringIntoViewDistanceY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BringIntoViewDistanceY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementFactory> : produce_base<D, Windows::UI::Xaml::IElementFactory>
{
    int32_t WINRT_CALL GetElement(void* args, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetElement, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::UI::Xaml::ElementFactoryGetArgs const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().GetElement(*reinterpret_cast<Windows::UI::Xaml::ElementFactoryGetArgs const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecycleElement(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecycleElement, WINRT_WRAP(void), Windows::UI::Xaml::ElementFactoryRecycleArgs const&);
            this->shim().RecycleElement(*reinterpret_cast<Windows::UI::Xaml::ElementFactoryRecycleArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementFactoryGetArgs> : produce_base<D, Windows::UI::Xaml::IElementFactoryGetArgs>
{
    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Data(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Parent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Parent(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementFactoryGetArgsFactory> : produce_base<D, Windows::UI::Xaml::IElementFactoryGetArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::ElementFactoryGetArgs), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::ElementFactoryGetArgs>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementFactoryRecycleArgs> : produce_base<D, Windows::UI::Xaml::IElementFactoryRecycleArgs>
{
    int32_t WINRT_CALL get_Element(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Element, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Element());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Element(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Element, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Element(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Parent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().Parent(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementFactoryRecycleArgsFactory> : produce_base<D, Windows::UI::Xaml::IElementFactoryRecycleArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::ElementFactoryRecycleArgs), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::ElementFactoryRecycleArgs>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementSoundPlayer> : produce_base<D, Windows::UI::Xaml::IElementSoundPlayer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementSoundPlayerStatics> : produce_base<D, Windows::UI::Xaml::IElementSoundPlayerStatics>
{
    int32_t WINRT_CALL get_Volume(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Volume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Volume(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Volume, WINRT_WRAP(void), double);
            this->shim().Volume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::UI::Xaml::ElementSoundPlayerState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::UI::Xaml::ElementSoundPlayerState));
            *value = detach_from<Windows::UI::Xaml::ElementSoundPlayerState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_State(Windows::UI::Xaml::ElementSoundPlayerState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(void), Windows::UI::Xaml::ElementSoundPlayerState const&);
            this->shim().State(*reinterpret_cast<Windows::UI::Xaml::ElementSoundPlayerState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Play(Windows::UI::Xaml::ElementSoundKind sound) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Play, WINRT_WRAP(void), Windows::UI::Xaml::ElementSoundKind const&);
            this->shim().Play(*reinterpret_cast<Windows::UI::Xaml::ElementSoundKind const*>(&sound));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IElementSoundPlayerStatics2> : produce_base<D, Windows::UI::Xaml::IElementSoundPlayerStatics2>
{
    int32_t WINRT_CALL get_SpatialAudioMode(Windows::UI::Xaml::ElementSpatialAudioMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatialAudioMode, WINRT_WRAP(Windows::UI::Xaml::ElementSpatialAudioMode));
            *value = detach_from<Windows::UI::Xaml::ElementSpatialAudioMode>(this->shim().SpatialAudioMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpatialAudioMode(Windows::UI::Xaml::ElementSpatialAudioMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatialAudioMode, WINRT_WRAP(void), Windows::UI::Xaml::ElementSpatialAudioMode const&);
            this->shim().SpatialAudioMode(*reinterpret_cast<Windows::UI::Xaml::ElementSpatialAudioMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IEventTrigger> : produce_base<D, Windows::UI::Xaml::IEventTrigger>
{
    int32_t WINRT_CALL get_RoutedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoutedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().RoutedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RoutedEvent(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoutedEvent, WINRT_WRAP(void), Windows::UI::Xaml::RoutedEvent const&);
            this->shim().RoutedEvent(*reinterpret_cast<Windows::UI::Xaml::RoutedEvent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Actions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Actions, WINRT_WRAP(Windows::UI::Xaml::TriggerActionCollection));
            *value = detach_from<Windows::UI::Xaml::TriggerActionCollection>(this->shim().Actions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IExceptionRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::IExceptionRoutedEventArgs>
{
    int32_t WINRT_CALL get_ErrorMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IExceptionRoutedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::IExceptionRoutedEventArgsFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement> : produce_base<D, Windows::UI::Xaml::IFrameworkElement>
{
    int32_t WINRT_CALL get_Triggers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Triggers, WINRT_WRAP(Windows::UI::Xaml::TriggerCollection));
            *value = detach_from<Windows::UI::Xaml::TriggerCollection>(this->shim().Triggers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Resources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resources, WINRT_WRAP(Windows::UI::Xaml::ResourceDictionary));
            *value = detach_from<Windows::UI::Xaml::ResourceDictionary>(this->shim().Resources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Resources(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resources, WINRT_WRAP(void), Windows::UI::Xaml::ResourceDictionary const&);
            this->shim().Resources(*reinterpret_cast<Windows::UI::Xaml::ResourceDictionary const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Tag(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ActualWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ActualHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Width(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(void), double);
            this->shim().Width(value);
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

    int32_t WINRT_CALL put_Height(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(void), double);
            this->shim().Height(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinWidth(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWidth, WINRT_WRAP(void), double);
            this->shim().MinWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxWidth(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWidth, WINRT_WRAP(void), double);
            this->shim().MaxWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MinHeight(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHeight, WINRT_WRAP(void), double);
            this->shim().MinHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxHeight(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHeight, WINRT_WRAP(void), double);
            this->shim().MaxHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalAlignment(Windows::UI::Xaml::HorizontalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignment, WINRT_WRAP(Windows::UI::Xaml::HorizontalAlignment));
            *value = detach_from<Windows::UI::Xaml::HorizontalAlignment>(this->shim().HorizontalAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HorizontalAlignment(Windows::UI::Xaml::HorizontalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignment, WINRT_WRAP(void), Windows::UI::Xaml::HorizontalAlignment const&);
            this->shim().HorizontalAlignment(*reinterpret_cast<Windows::UI::Xaml::HorizontalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalAlignment(Windows::UI::Xaml::VerticalAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignment, WINRT_WRAP(Windows::UI::Xaml::VerticalAlignment));
            *value = detach_from<Windows::UI::Xaml::VerticalAlignment>(this->shim().VerticalAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VerticalAlignment(Windows::UI::Xaml::VerticalAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignment, WINRT_WRAP(void), Windows::UI::Xaml::VerticalAlignment const&);
            this->shim().VerticalAlignment(*reinterpret_cast<Windows::UI::Xaml::VerticalAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Margin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Margin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().Margin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Margin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Margin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().Margin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BaseUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().BaseUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataContext, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().DataContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataContext(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataContext, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().DataContext(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Style(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(Windows::UI::Xaml::Style));
            *value = detach_from<Windows::UI::Xaml::Style>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Style(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(void), Windows::UI::Xaml::Style const&);
            this->shim().Style(*reinterpret_cast<Windows::UI::Xaml::Style const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowDirection(Windows::UI::Xaml::FlowDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(Windows::UI::Xaml::FlowDirection));
            *value = detach_from<Windows::UI::Xaml::FlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FlowDirection(Windows::UI::Xaml::FlowDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirection, WINRT_WRAP(void), Windows::UI::Xaml::FlowDirection const&);
            this->shim().FlowDirection(*reinterpret_cast<Windows::UI::Xaml::FlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Loaded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Loaded, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Loaded(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Loaded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Loaded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Loaded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Unloaded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unloaded, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Unloaded(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Unloaded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Unloaded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Unloaded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SizeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::SizeChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<Windows::UI::Xaml::SizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SizeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LayoutUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LayoutUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LayoutUpdated(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LayoutUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LayoutUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LayoutUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL FindName(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindName, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().FindName(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBinding(void* dp, void* binding) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBinding, WINRT_WRAP(void), Windows::UI::Xaml::DependencyProperty const&, Windows::UI::Xaml::Data::BindingBase const&);
            this->shim().SetBinding(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<Windows::UI::Xaml::Data::BindingBase const*>(&binding));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement2> : produce_base<D, Windows::UI::Xaml::IFrameworkElement2>
{
    int32_t WINRT_CALL get_RequestedTheme(Windows::UI::Xaml::ElementTheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedTheme, WINRT_WRAP(Windows::UI::Xaml::ElementTheme));
            *value = detach_from<Windows::UI::Xaml::ElementTheme>(this->shim().RequestedTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestedTheme(Windows::UI::Xaml::ElementTheme value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedTheme, WINRT_WRAP(void), Windows::UI::Xaml::ElementTheme const&);
            this->shim().RequestedTheme(*reinterpret_cast<Windows::UI::Xaml::ElementTheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataContextChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataContextChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::DataContextChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DataContextChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::DataContextChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataContextChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataContextChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataContextChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetBindingExpression(void* dp, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBindingExpression, WINRT_WRAP(Windows::UI::Xaml::Data::BindingExpression), Windows::UI::Xaml::DependencyProperty const&);
            *result = detach_from<Windows::UI::Xaml::Data::BindingExpression>(this->shim().GetBindingExpression(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement3> : produce_base<D, Windows::UI::Xaml::IFrameworkElement3>
{
    int32_t WINRT_CALL add_Loading(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Loading, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Loading(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Loading(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Loading, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Loading(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement4> : produce_base<D, Windows::UI::Xaml::IFrameworkElement4>
{
    int32_t WINRT_CALL get_AllowFocusOnInteraction(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteraction, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowFocusOnInteraction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowFocusOnInteraction(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteraction, WINRT_WRAP(void), bool);
            this->shim().AllowFocusOnInteraction(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualMargin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualMargin, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().FocusVisualMargin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualMargin(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualMargin, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().FocusVisualMargin(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualSecondaryThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().FocusVisualSecondaryThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualSecondaryThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryThickness, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().FocusVisualSecondaryThickness(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualPrimaryThickness(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryThickness, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().FocusVisualPrimaryThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualPrimaryThickness(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryThickness, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().FocusVisualPrimaryThickness(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualSecondaryBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().FocusVisualSecondaryBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualSecondaryBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().FocusVisualSecondaryBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualPrimaryBrush(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryBrush, WINRT_WRAP(Windows::UI::Xaml::Media::Brush));
            *value = detach_from<Windows::UI::Xaml::Media::Brush>(this->shim().FocusVisualPrimaryBrush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FocusVisualPrimaryBrush(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryBrush, WINRT_WRAP(void), Windows::UI::Xaml::Media::Brush const&);
            this->shim().FocusVisualPrimaryBrush(*reinterpret_cast<Windows::UI::Xaml::Media::Brush const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowFocusWhenDisabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusWhenDisabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowFocusWhenDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowFocusWhenDisabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusWhenDisabled, WINRT_WRAP(void), bool);
            this->shim().AllowFocusWhenDisabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement6> : produce_base<D, Windows::UI::Xaml::IFrameworkElement6>
{
    int32_t WINRT_CALL get_ActualTheme(Windows::UI::Xaml::ElementTheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualTheme, WINRT_WRAP(Windows::UI::Xaml::ElementTheme));
            *value = detach_from<Windows::UI::Xaml::ElementTheme>(this->shim().ActualTheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ActualThemeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualThemeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ActualThemeChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ActualThemeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ActualThemeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ActualThemeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElement7> : produce_base<D, Windows::UI::Xaml::IFrameworkElement7>
{
    int32_t WINRT_CALL get_IsLoaded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLoaded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLoaded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_EffectiveViewportChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EffectiveViewportChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EffectiveViewportChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::EffectiveViewportChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EffectiveViewportChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EffectiveViewportChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EffectiveViewportChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementFactory> : produce_base<D, Windows::UI::Xaml::IFrameworkElementFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::FrameworkElement), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::FrameworkElement>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementOverrides> : produce_base<D, Windows::UI::Xaml::IFrameworkElementOverrides>
{
    int32_t WINRT_CALL MeasureOverride(Windows::Foundation::Size availableSize, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeasureOverride, WINRT_WRAP(Windows::Foundation::Size), Windows::Foundation::Size const&);
            *result = detach_from<Windows::Foundation::Size>(this->shim().MeasureOverride(*reinterpret_cast<Windows::Foundation::Size const*>(&availableSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ArrangeOverride(Windows::Foundation::Size finalSize, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArrangeOverride, WINRT_WRAP(Windows::Foundation::Size), Windows::Foundation::Size const&);
            *result = detach_from<Windows::Foundation::Size>(this->shim().ArrangeOverride(*reinterpret_cast<Windows::Foundation::Size const*>(&finalSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnApplyTemplate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnApplyTemplate, WINRT_WRAP(void));
            this->shim().OnApplyTemplate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementOverrides2> : produce_base<D, Windows::UI::Xaml::IFrameworkElementOverrides2>
{
    int32_t WINRT_CALL GoToElementStateCore(void* stateName, bool useTransitions, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoToElementStateCore, WINRT_WRAP(bool), hstring const&, bool);
            *result = detach_from<bool>(this->shim().GoToElementStateCore(*reinterpret_cast<hstring const*>(&stateName), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementProtected7> : produce_base<D, Windows::UI::Xaml::IFrameworkElementProtected7>
{
    int32_t WINRT_CALL InvalidateViewport() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateViewport, WINRT_WRAP(void));
            this->shim().InvalidateViewport();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementStatics> : produce_base<D, Windows::UI::Xaml::IFrameworkElementStatics>
{
    int32_t WINRT_CALL get_TagProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TagProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TagProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LanguageProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ActualWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ActualHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().WidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaxWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MinHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MaxHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HorizontalAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalAlignmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalAlignmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VerticalAlignmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataContextProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataContextProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DataContextProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowDirectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowDirectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FlowDirectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementStatics2> : produce_base<D, Windows::UI::Xaml::IFrameworkElementStatics2>
{
    int32_t WINRT_CALL get_RequestedThemeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedThemeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RequestedThemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementStatics4> : produce_base<D, Windows::UI::Xaml::IFrameworkElementStatics4>
{
    int32_t WINRT_CALL get_AllowFocusOnInteractionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusOnInteractionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusOnInteractionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualMarginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualMarginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualMarginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualSecondaryThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualSecondaryThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualPrimaryThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualPrimaryThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualSecondaryBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualSecondaryBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualSecondaryBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FocusVisualPrimaryBrushProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusVisualPrimaryBrushProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FocusVisualPrimaryBrushProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowFocusWhenDisabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFocusWhenDisabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AllowFocusWhenDisabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementStatics5> : produce_base<D, Windows::UI::Xaml::IFrameworkElementStatics5>
{
    int32_t WINRT_CALL DeferTree(void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferTree, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().DeferTree(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkElementStatics6> : produce_base<D, Windows::UI::Xaml::IFrameworkElementStatics6>
{
    int32_t WINRT_CALL get_ActualThemeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualThemeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ActualThemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkTemplate> : produce_base<D, Windows::UI::Xaml::IFrameworkTemplate>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkTemplateFactory> : produce_base<D, Windows::UI::Xaml::IFrameworkTemplateFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::FrameworkTemplate), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::FrameworkTemplate>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkView> : produce_base<D, Windows::UI::Xaml::IFrameworkView>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IFrameworkViewSource> : produce_base<D, Windows::UI::Xaml::IFrameworkViewSource>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IGridLengthHelper> : produce_base<D, Windows::UI::Xaml::IGridLengthHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IGridLengthHelperStatics> : produce_base<D, Windows::UI::Xaml::IGridLengthHelperStatics>
{
    int32_t WINRT_CALL get_Auto(struct struct_Windows_UI_Xaml_GridLength* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Auto, WINRT_WRAP(Windows::UI::Xaml::GridLength));
            *value = detach_from<Windows::UI::Xaml::GridLength>(this->shim().Auto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromPixels(double pixels, struct struct_Windows_UI_Xaml_GridLength* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromPixels, WINRT_WRAP(Windows::UI::Xaml::GridLength), double);
            *result = detach_from<Windows::UI::Xaml::GridLength>(this->shim().FromPixels(pixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromValueAndType(double value, Windows::UI::Xaml::GridUnitType type, struct struct_Windows_UI_Xaml_GridLength* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromValueAndType, WINRT_WRAP(Windows::UI::Xaml::GridLength), double, Windows::UI::Xaml::GridUnitType const&);
            *result = detach_from<Windows::UI::Xaml::GridLength>(this->shim().FromValueAndType(value, *reinterpret_cast<Windows::UI::Xaml::GridUnitType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAbsolute(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAbsolute, WINRT_WRAP(bool), Windows::UI::Xaml::GridLength const&);
            *result = detach_from<bool>(this->shim().GetIsAbsolute(*reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAuto(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAuto, WINRT_WRAP(bool), Windows::UI::Xaml::GridLength const&);
            *result = detach_from<bool>(this->shim().GetIsAuto(*reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsStar(struct struct_Windows_UI_Xaml_GridLength target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsStar, WINRT_WRAP(bool), Windows::UI::Xaml::GridLength const&);
            *result = detach_from<bool>(this->shim().GetIsStar(*reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(struct struct_Windows_UI_Xaml_GridLength target, struct struct_Windows_UI_Xaml_GridLength value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::UI::Xaml::GridLength const&, Windows::UI::Xaml::GridLength const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&target), *reinterpret_cast<Windows::UI::Xaml::GridLength const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IMediaFailedRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::IMediaFailedRoutedEventArgs>
{
    int32_t WINRT_CALL get_ErrorTrace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorTrace, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorTrace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPointHelper> : produce_base<D, Windows::UI::Xaml::IPointHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPointHelperStatics> : produce_base<D, Windows::UI::Xaml::IPointHelperStatics>
{
    int32_t WINRT_CALL FromCoordinates(float x, float y, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromCoordinates, WINRT_WRAP(Windows::Foundation::Point), float, float);
            *result = detach_from<Windows::Foundation::Point>(this->shim().FromCoordinates(x, y));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPropertyMetadata> : produce_base<D, Windows::UI::Xaml::IPropertyMetadata>
{
    int32_t WINRT_CALL get_DefaultValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().DefaultValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CreateDefaultValueCallback(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDefaultValueCallback, WINRT_WRAP(Windows::UI::Xaml::CreateDefaultValueCallback));
            *value = detach_from<Windows::UI::Xaml::CreateDefaultValueCallback>(this->shim().CreateDefaultValueCallback());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPropertyMetadataFactory> : produce_base<D, Windows::UI::Xaml::IPropertyMetadataFactory>
{
    int32_t WINRT_CALL CreateInstanceWithDefaultValue(void* defaultValue, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDefaultValue, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().CreateInstanceWithDefaultValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDefaultValueAndCallback(void* defaultValue, void* propertyChangedCallback, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDefaultValueAndCallback, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::PropertyChangedCallback const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().CreateInstanceWithDefaultValueAndCallback(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPropertyMetadataStatics> : produce_base<D, Windows::UI::Xaml::IPropertyMetadataStatics>
{
    int32_t WINRT_CALL CreateWithDefaultValue(void* defaultValue, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&defaultValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithDefaultValueAndCallback(void* defaultValue, void* propertyChangedCallback, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::PropertyChangedCallback const&);
            *result = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&defaultValue), *reinterpret_cast<Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithFactory(void* createDefaultValueCallback, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::UI::Xaml::CreateDefaultValueCallback const&);
            *result = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<Windows::UI::Xaml::CreateDefaultValueCallback const*>(&createDefaultValueCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithFactoryAndCallback(void* createDefaultValueCallback, void* propertyChangedCallback, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::UI::Xaml::PropertyMetadata), Windows::UI::Xaml::CreateDefaultValueCallback const&, Windows::UI::Xaml::PropertyChangedCallback const&);
            *result = detach_from<Windows::UI::Xaml::PropertyMetadata>(this->shim().Create(*reinterpret_cast<Windows::UI::Xaml::CreateDefaultValueCallback const*>(&createDefaultValueCallback), *reinterpret_cast<Windows::UI::Xaml::PropertyChangedCallback const*>(&propertyChangedCallback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPropertyPath> : produce_base<D, Windows::UI::Xaml::IPropertyPath>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IPropertyPathFactory> : produce_base<D, Windows::UI::Xaml::IPropertyPathFactory>
{
    int32_t WINRT_CALL CreateInstance(void* path, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::PropertyPath), hstring const&);
            *value = detach_from<Windows::UI::Xaml::PropertyPath>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IRectHelper> : produce_base<D, Windows::UI::Xaml::IRectHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IRectHelperStatics> : produce_base<D, Windows::UI::Xaml::IRectHelperStatics>
{
    int32_t WINRT_CALL get_Empty(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Empty, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromCoordinatesAndDimensions(float x, float y, float width, float height, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromCoordinatesAndDimensions, WINRT_WRAP(Windows::Foundation::Rect), float, float, float, float);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().FromCoordinatesAndDimensions(x, y, width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromPoints(Windows::Foundation::Point point1, Windows::Foundation::Point point2, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromPoints, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Point const&, Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().FromPoints(*reinterpret_cast<Windows::Foundation::Point const*>(&point1), *reinterpret_cast<Windows::Foundation::Point const*>(&point2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromLocationAndSize(Windows::Foundation::Point location, Windows::Foundation::Size size, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromLocationAndSize, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Point const&, Windows::Foundation::Size const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().FromLocationAndSize(*reinterpret_cast<Windows::Foundation::Point const*>(&location), *reinterpret_cast<Windows::Foundation::Size const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsEmpty(Windows::Foundation::Rect target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsEmpty, WINRT_WRAP(bool), Windows::Foundation::Rect const&);
            *result = detach_from<bool>(this->shim().GetIsEmpty(*reinterpret_cast<Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBottom(Windows::Foundation::Rect target, float* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBottom, WINRT_WRAP(float), Windows::Foundation::Rect const&);
            *result = detach_from<float>(this->shim().GetBottom(*reinterpret_cast<Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLeft(Windows::Foundation::Rect target, float* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLeft, WINRT_WRAP(float), Windows::Foundation::Rect const&);
            *result = detach_from<float>(this->shim().GetLeft(*reinterpret_cast<Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRight(Windows::Foundation::Rect target, float* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRight, WINRT_WRAP(float), Windows::Foundation::Rect const&);
            *result = detach_from<float>(this->shim().GetRight(*reinterpret_cast<Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTop(Windows::Foundation::Rect target, float* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTop, WINRT_WRAP(float), Windows::Foundation::Rect const&);
            *result = detach_from<float>(this->shim().GetTop(*reinterpret_cast<Windows::Foundation::Rect const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Contains(Windows::Foundation::Rect target, Windows::Foundation::Point point, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contains, WINRT_WRAP(bool), Windows::Foundation::Rect const&, Windows::Foundation::Point const&);
            *result = detach_from<bool>(this->shim().Contains(*reinterpret_cast<Windows::Foundation::Rect const*>(&target), *reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(Windows::Foundation::Rect target, Windows::Foundation::Rect value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::Foundation::Rect const&, Windows::Foundation::Rect const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::Foundation::Rect const*>(&target), *reinterpret_cast<Windows::Foundation::Rect const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Intersect(Windows::Foundation::Rect target, Windows::Foundation::Rect rect, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Intersect, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().Intersect(*reinterpret_cast<Windows::Foundation::Rect const*>(&target), *reinterpret_cast<Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnionWithPoint(Windows::Foundation::Rect target, Windows::Foundation::Point point, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Union, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&, Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().Union(*reinterpret_cast<Windows::Foundation::Rect const*>(&target), *reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnionWithRect(Windows::Foundation::Rect target, Windows::Foundation::Rect rect, Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Union, WINRT_WRAP(Windows::Foundation::Rect), Windows::Foundation::Rect const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Rect>(this->shim().Union(*reinterpret_cast<Windows::Foundation::Rect const*>(&target), *reinterpret_cast<Windows::Foundation::Rect const*>(&rect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IResourceDictionary> : produce_base<D, Windows::UI::Xaml::IResourceDictionary>
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

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Source(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MergedDictionaries(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MergedDictionaries, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::ResourceDictionary>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::ResourceDictionary>>(this->shim().MergedDictionaries());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThemeDictionaries(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThemeDictionaries, WINRT_WRAP(Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>>(this->shim().ThemeDictionaries());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IResourceDictionaryFactory> : produce_base<D, Windows::UI::Xaml::IResourceDictionaryFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::ResourceDictionary), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::ResourceDictionary>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IRoutedEvent> : produce_base<D, Windows::UI::Xaml::IRoutedEvent>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IRoutedEventArgs> : produce_base<D, Windows::UI::Xaml::IRoutedEventArgs>
{
    int32_t WINRT_CALL get_OriginalSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalSource, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().OriginalSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IRoutedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::IRoutedEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::RoutedEventArgs), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::RoutedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IScalarTransition> : produce_base<D, Windows::UI::Xaml::IScalarTransition>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IScalarTransitionFactory> : produce_base<D, Windows::UI::Xaml::IScalarTransitionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::ScalarTransition), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::ScalarTransition>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetter> : produce_base<D, Windows::UI::Xaml::ISetter>
{
    int32_t WINRT_CALL get_Property(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Property, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Property());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Property(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Property, WINRT_WRAP(void), Windows::UI::Xaml::DependencyProperty const&);
            this->shim().Property(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetter2> : produce_base<D, Windows::UI::Xaml::ISetter2>
{
    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(Windows::UI::Xaml::TargetPropertyPath));
            *value = detach_from<Windows::UI::Xaml::TargetPropertyPath>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Target(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(void), Windows::UI::Xaml::TargetPropertyPath const&);
            this->shim().Target(*reinterpret_cast<Windows::UI::Xaml::TargetPropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetterBase> : produce_base<D, Windows::UI::Xaml::ISetterBase>
{
    int32_t WINRT_CALL get_IsSealed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSealed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetterBaseCollection> : produce_base<D, Windows::UI::Xaml::ISetterBaseCollection>
{
    int32_t WINRT_CALL get_IsSealed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSealed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetterBaseFactory> : produce_base<D, Windows::UI::Xaml::ISetterBaseFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISetterFactory> : produce_base<D, Windows::UI::Xaml::ISetterFactory>
{
    int32_t WINRT_CALL CreateInstance(void* targetProperty, void* value, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Setter), Windows::UI::Xaml::DependencyProperty const&, Windows::Foundation::IInspectable const&);
            *instance = detach_from<Windows::UI::Xaml::Setter>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&targetProperty), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISizeChangedEventArgs> : produce_base<D, Windows::UI::Xaml::ISizeChangedEventArgs>
{
    int32_t WINRT_CALL get_PreviousSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().PreviousSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().NewSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISizeHelper> : produce_base<D, Windows::UI::Xaml::ISizeHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ISizeHelperStatics> : produce_base<D, Windows::UI::Xaml::ISizeHelperStatics>
{
    int32_t WINRT_CALL get_Empty(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Empty, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().Empty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromDimensions(float width, float height, Windows::Foundation::Size* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromDimensions, WINRT_WRAP(Windows::Foundation::Size), float, float);
            *result = detach_from<Windows::Foundation::Size>(this->shim().FromDimensions(width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsEmpty(Windows::Foundation::Size target, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsEmpty, WINRT_WRAP(bool), Windows::Foundation::Size const&);
            *result = detach_from<bool>(this->shim().GetIsEmpty(*reinterpret_cast<Windows::Foundation::Size const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Equals(Windows::Foundation::Size target, Windows::Foundation::Size value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Equals, WINRT_WRAP(bool), Windows::Foundation::Size const&, Windows::Foundation::Size const&);
            *result = detach_from<bool>(this->shim().Equals(*reinterpret_cast<Windows::Foundation::Size const*>(&target), *reinterpret_cast<Windows::Foundation::Size const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStateTrigger> : produce_base<D, Windows::UI::Xaml::IStateTrigger>
{
    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsActive(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(void), bool);
            this->shim().IsActive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStateTriggerBase> : produce_base<D, Windows::UI::Xaml::IStateTriggerBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStateTriggerBaseFactory> : produce_base<D, Windows::UI::Xaml::IStateTriggerBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::StateTriggerBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::StateTriggerBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStateTriggerBaseProtected> : produce_base<D, Windows::UI::Xaml::IStateTriggerBaseProtected>
{
    int32_t WINRT_CALL SetActive(bool IsActive) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActive, WINRT_WRAP(void), bool);
            this->shim().SetActive(IsActive);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStateTriggerStatics> : produce_base<D, Windows::UI::Xaml::IStateTriggerStatics>
{
    int32_t WINRT_CALL get_IsActiveProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActiveProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsActiveProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStyle> : produce_base<D, Windows::UI::Xaml::IStyle>
{
    int32_t WINRT_CALL get_IsSealed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSealed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSealed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Setters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Setters, WINRT_WRAP(Windows::UI::Xaml::SetterBaseCollection));
            *value = detach_from<Windows::UI::Xaml::SetterBaseCollection>(this->shim().Setters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetType, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().TargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetType(struct struct_Windows_UI_Xaml_Interop_TypeName value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetType, WINRT_WRAP(void), Windows::UI::Xaml::Interop::TypeName const&);
            this->shim().TargetType(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BasedOn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BasedOn, WINRT_WRAP(Windows::UI::Xaml::Style));
            *value = detach_from<Windows::UI::Xaml::Style>(this->shim().BasedOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BasedOn(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BasedOn, WINRT_WRAP(void), Windows::UI::Xaml::Style const&);
            this->shim().BasedOn(*reinterpret_cast<Windows::UI::Xaml::Style const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Seal() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Seal, WINRT_WRAP(void));
            this->shim().Seal();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IStyleFactory> : produce_base<D, Windows::UI::Xaml::IStyleFactory>
{
    int32_t WINRT_CALL CreateInstance(struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Style), Windows::UI::Xaml::Interop::TypeName const&);
            *value = detach_from<Windows::UI::Xaml::Style>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&targetType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITargetPropertyPath> : produce_base<D, Windows::UI::Xaml::ITargetPropertyPath>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::UI::Xaml::PropertyPath));
            *value = detach_from<Windows::UI::Xaml::PropertyPath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::UI::Xaml::PropertyPath const&);
            this->shim().Path(*reinterpret_cast<Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Target(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Target(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITargetPropertyPathFactory> : produce_base<D, Windows::UI::Xaml::ITargetPropertyPathFactory>
{
    int32_t WINRT_CALL CreateInstance(void* targetProperty, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::TargetPropertyPath), Windows::UI::Xaml::DependencyProperty const&);
            *value = detach_from<Windows::UI::Xaml::TargetPropertyPath>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&targetProperty)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IThicknessHelper> : produce_base<D, Windows::UI::Xaml::IThicknessHelper>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IThicknessHelperStatics> : produce_base<D, Windows::UI::Xaml::IThicknessHelperStatics>
{
    int32_t WINRT_CALL FromLengths(double left, double top, double right, double bottom, struct struct_Windows_UI_Xaml_Thickness* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromLengths, WINRT_WRAP(Windows::UI::Xaml::Thickness), double, double, double, double);
            *result = detach_from<Windows::UI::Xaml::Thickness>(this->shim().FromLengths(left, top, right, bottom));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromUniformLength(double uniformLength, struct struct_Windows_UI_Xaml_Thickness* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromUniformLength, WINRT_WRAP(Windows::UI::Xaml::Thickness), double);
            *result = detach_from<Windows::UI::Xaml::Thickness>(this->shim().FromUniformLength(uniformLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITriggerAction> : produce_base<D, Windows::UI::Xaml::ITriggerAction>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITriggerActionFactory> : produce_base<D, Windows::UI::Xaml::ITriggerActionFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITriggerBase> : produce_base<D, Windows::UI::Xaml::ITriggerBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::ITriggerBaseFactory> : produce_base<D, Windows::UI::Xaml::ITriggerBaseFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement> : produce_base<D, Windows::UI::Xaml::IUIElement>
{
    int32_t WINRT_CALL get_DesiredSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().DesiredSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowDrop(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowDrop, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowDrop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowDrop(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowDrop, WINRT_WRAP(void), bool);
            this->shim().AllowDrop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Opacity(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Opacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Opacity(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opacity, WINRT_WRAP(void), double);
            this->shim().Opacity(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clip(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clip, WINRT_WRAP(Windows::UI::Xaml::Media::RectangleGeometry));
            *value = detach_from<Windows::UI::Xaml::Media::RectangleGeometry>(this->shim().Clip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Clip(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clip, WINRT_WRAP(void), Windows::UI::Xaml::Media::RectangleGeometry const&);
            this->shim().Clip(*reinterpret_cast<Windows::UI::Xaml::Media::RectangleGeometry const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderTransform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransform, WINRT_WRAP(Windows::UI::Xaml::Media::Transform));
            *value = detach_from<Windows::UI::Xaml::Media::Transform>(this->shim().RenderTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RenderTransform(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransform, WINRT_WRAP(void), Windows::UI::Xaml::Media::Transform const&);
            this->shim().RenderTransform(*reinterpret_cast<Windows::UI::Xaml::Media::Transform const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Projection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Projection, WINRT_WRAP(Windows::UI::Xaml::Media::Projection));
            *value = detach_from<Windows::UI::Xaml::Media::Projection>(this->shim().Projection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Projection(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Projection, WINRT_WRAP(void), Windows::UI::Xaml::Media::Projection const&);
            this->shim().Projection(*reinterpret_cast<Windows::UI::Xaml::Media::Projection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderTransformOrigin(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransformOrigin, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().RenderTransformOrigin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RenderTransformOrigin(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransformOrigin, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().RenderTransformOrigin(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHitTestVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHitTestVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHitTestVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHitTestVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHitTestVisible, WINRT_WRAP(void), bool);
            this->shim().IsHitTestVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visibility(Windows::UI::Xaml::Visibility* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visibility, WINRT_WRAP(Windows::UI::Xaml::Visibility));
            *value = detach_from<Windows::UI::Xaml::Visibility>(this->shim().Visibility());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visibility(Windows::UI::Xaml::Visibility value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visibility, WINRT_WRAP(void), Windows::UI::Xaml::Visibility const&);
            this->shim().Visibility(*reinterpret_cast<Windows::UI::Xaml::Visibility const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().RenderSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UseLayoutRounding(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseLayoutRounding, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UseLayoutRounding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UseLayoutRounding(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseLayoutRounding, WINRT_WRAP(void), bool);
            this->shim().UseLayoutRounding(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transitions, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::TransitionCollection));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::TransitionCollection>(this->shim().Transitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Transitions(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transitions, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::TransitionCollection const&);
            this->shim().Transitions(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::TransitionCollection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CacheMode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheMode, WINRT_WRAP(Windows::UI::Xaml::Media::CacheMode));
            *value = detach_from<Windows::UI::Xaml::Media::CacheMode>(this->shim().CacheMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CacheMode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheMode, WINRT_WRAP(void), Windows::UI::Xaml::Media::CacheMode const&);
            this->shim().CacheMode(*reinterpret_cast<Windows::UI::Xaml::Media::CacheMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTapEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTapEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTapEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTapEnabled, WINRT_WRAP(void), bool);
            this->shim().IsTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleTapEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleTapEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDoubleTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDoubleTapEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleTapEnabled, WINRT_WRAP(void), bool);
            this->shim().IsDoubleTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRightTapEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRightTapEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRightTapEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRightTapEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRightTapEnabled, WINRT_WRAP(void), bool);
            this->shim().IsRightTapEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHoldingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHoldingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHoldingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHoldingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHoldingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsHoldingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationMode(Windows::UI::Xaml::Input::ManipulationModes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationMode, WINRT_WRAP(Windows::UI::Xaml::Input::ManipulationModes));
            *value = detach_from<Windows::UI::Xaml::Input::ManipulationModes>(this->shim().ManipulationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ManipulationMode(Windows::UI::Xaml::Input::ManipulationModes value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationMode, WINRT_WRAP(void), Windows::UI::Xaml::Input::ManipulationModes const&);
            this->shim().ManipulationMode(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationModes const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCaptures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCaptures, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Input::Pointer>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Input::Pointer>>(this->shim().PointerCaptures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_KeyUp(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::KeyEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().KeyUp(*reinterpret_cast<Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyUp(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyUp, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_KeyDown(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::KeyEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().KeyDown(*reinterpret_cast<Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_KeyDown(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(KeyDown, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().KeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
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

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DragEnter(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragEnter, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::DragEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragEnter(*reinterpret_cast<Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragEnter(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragEnter, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragEnter(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DragLeave(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragLeave, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::DragEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragLeave(*reinterpret_cast<Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragLeave(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragLeave, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragLeave(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DragOver(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOver, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::DragEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DragOver(*reinterpret_cast<Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragOver(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragOver, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragOver(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Drop(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Drop, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::DragEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Drop(*reinterpret_cast<Windows::UI::Xaml::DragEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Drop(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Drop, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Drop(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerPressed(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerMoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerMoved(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerMoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerMoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerReleased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerReleased(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerReleased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerReleased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerReleased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerEntered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerEntered(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerExited(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerCaptureLost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerCaptureLost(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerCaptureLost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerCaptureLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerCaptureLost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerCanceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCanceled, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerCanceled(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerCanceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PointerWheelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::PointerEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PointerWheelChanged(*reinterpret_cast<Windows::UI::Xaml::Input::PointerEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PointerWheelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PointerWheelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PointerWheelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Tapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::TappedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Tapped(*reinterpret_cast<Windows::UI::Xaml::Input::TappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Tapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Tapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Tapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DoubleTapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleTapped, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::DoubleTappedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DoubleTapped(*reinterpret_cast<Windows::UI::Xaml::Input::DoubleTappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DoubleTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DoubleTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DoubleTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Holding(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Holding, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::HoldingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Holding(*reinterpret_cast<Windows::UI::Xaml::Input::HoldingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Holding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Holding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Holding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RightTapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightTapped, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::RightTappedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().RightTapped(*reinterpret_cast<Windows::UI::Xaml::Input::RightTappedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RightTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RightTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStarting, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::ManipulationStartingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarting(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationStartingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationInertiaStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationInertiaStarting, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationInertiaStarting(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationInertiaStartingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationInertiaStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationInertiaStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationInertiaStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationStarted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::ManipulationStartedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationStarted(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationStartedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationStarted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationStarted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationStarted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationDelta(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationDelta, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationDelta(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationDeltaEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationDelta(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationDelta, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationDelta(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ManipulationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ManipulationCompleted(*reinterpret_cast<Windows::UI::Xaml::Input::ManipulationCompletedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ManipulationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ManipulationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ManipulationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Measure(Windows::Foundation::Size availableSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Measure, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().Measure(*reinterpret_cast<Windows::Foundation::Size const*>(&availableSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Arrange(Windows::Foundation::Rect finalRect) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arrange, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Arrange(*reinterpret_cast<Windows::Foundation::Rect const*>(&finalRect));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CapturePointer(void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturePointer, WINRT_WRAP(bool), Windows::UI::Xaml::Input::Pointer const&);
            *result = detach_from<bool>(this->shim().CapturePointer(*reinterpret_cast<Windows::UI::Xaml::Input::Pointer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReleasePointerCapture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleasePointerCapture, WINRT_WRAP(void), Windows::UI::Xaml::Input::Pointer const&);
            this->shim().ReleasePointerCapture(*reinterpret_cast<Windows::UI::Xaml::Input::Pointer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReleasePointerCaptures() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleasePointerCaptures, WINRT_WRAP(void));
            this->shim().ReleasePointerCaptures();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddHandler(void* routedEvent, void* handler, bool handledEventsToo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddHandler, WINRT_WRAP(void), Windows::UI::Xaml::RoutedEvent const&, Windows::Foundation::IInspectable const&, bool);
            this->shim().AddHandler(*reinterpret_cast<Windows::UI::Xaml::RoutedEvent const*>(&routedEvent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&handler), handledEventsToo);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveHandler(void* routedEvent, void* handler) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveHandler, WINRT_WRAP(void), Windows::UI::Xaml::RoutedEvent const&, Windows::Foundation::IInspectable const&);
            this->shim().RemoveHandler(*reinterpret_cast<Windows::UI::Xaml::RoutedEvent const*>(&routedEvent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransformToVisual(void* visual, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformToVisual, WINRT_WRAP(Windows::UI::Xaml::Media::GeneralTransform), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Xaml::Media::GeneralTransform>(this->shim().TransformToVisual(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&visual)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidateMeasure() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateMeasure, WINRT_WRAP(void));
            this->shim().InvalidateMeasure();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidateArrange() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateArrange, WINRT_WRAP(void));
            this->shim().InvalidateArrange();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateLayout() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateLayout, WINRT_WRAP(void));
            this->shim().UpdateLayout();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement10> : produce_base<D, Windows::UI::Xaml::IUIElement10>
{
    int32_t WINRT_CALL get_ActualOffset(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualOffset, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().ActualOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualSize(Windows::Foundation::Numerics::float2* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualSize, WINRT_WRAP(Windows::Foundation::Numerics::float2));
            *value = detach_from<Windows::Foundation::Numerics::float2>(this->shim().ActualSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XamlRoot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XamlRoot, WINRT_WRAP(Windows::UI::Xaml::XamlRoot));
            *value = detach_from<Windows::UI::Xaml::XamlRoot>(this->shim().XamlRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XamlRoot(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XamlRoot, WINRT_WRAP(void), Windows::UI::Xaml::XamlRoot const&);
            this->shim().XamlRoot(*reinterpret_cast<Windows::UI::Xaml::XamlRoot const*>(&value));
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

    int32_t WINRT_CALL get_Shadow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(Windows::UI::Xaml::Media::Shadow));
            *value = detach_from<Windows::UI::Xaml::Media::Shadow>(this->shim().Shadow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Shadow(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shadow, WINRT_WRAP(void), Windows::UI::Xaml::Media::Shadow const&);
            this->shim().Shadow(*reinterpret_cast<Windows::UI::Xaml::Media::Shadow const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement2> : produce_base<D, Windows::UI::Xaml::IUIElement2>
{
    int32_t WINRT_CALL get_CompositeMode(Windows::UI::Xaml::Media::ElementCompositeMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeMode, WINRT_WRAP(Windows::UI::Xaml::Media::ElementCompositeMode));
            *value = detach_from<Windows::UI::Xaml::Media::ElementCompositeMode>(this->shim().CompositeMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompositeMode(Windows::UI::Xaml::Media::ElementCompositeMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeMode, WINRT_WRAP(void), Windows::UI::Xaml::Media::ElementCompositeMode const&);
            this->shim().CompositeMode(*reinterpret_cast<Windows::UI::Xaml::Media::ElementCompositeMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelDirectManipulations(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelDirectManipulations, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CancelDirectManipulations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement3> : produce_base<D, Windows::UI::Xaml::IUIElement3>
{
    int32_t WINRT_CALL get_Transform3D(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform3D, WINRT_WRAP(Windows::UI::Xaml::Media::Media3D::Transform3D));
            *value = detach_from<Windows::UI::Xaml::Media::Media3D::Transform3D>(this->shim().Transform3D());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Transform3D(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform3D, WINRT_WRAP(void), Windows::UI::Xaml::Media::Media3D::Transform3D const&);
            this->shim().Transform3D(*reinterpret_cast<Windows::UI::Xaml::Media::Media3D::Transform3D const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDrag(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDrag, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDrag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanDrag(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDrag, WINRT_WRAP(void), bool);
            this->shim().CanDrag(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DragStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DragStartingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DragStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DragStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DragStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DragStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DragStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DropCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DropCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DropCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DropCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DropCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DropCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DropCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL StartDragAsync(void* pointerPoint, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDragAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackageOperation>), Windows::UI::Input::PointerPoint const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::DataTransfer::DataPackageOperation>>(this->shim().StartDragAsync(*reinterpret_cast<Windows::UI::Input::PointerPoint const*>(&pointerPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement4> : produce_base<D, Windows::UI::Xaml::IUIElement4>
{
    int32_t WINRT_CALL get_ContextFlyout(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextFlyout, WINRT_WRAP(Windows::UI::Xaml::Controls::Primitives::FlyoutBase));
            *value = detach_from<Windows::UI::Xaml::Controls::Primitives::FlyoutBase>(this->shim().ContextFlyout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContextFlyout(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextFlyout, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Primitives::FlyoutBase const&);
            this->shim().ContextFlyout(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::FlyoutBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvoked(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvoked, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExitDisplayModeOnAccessKeyInvoked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitDisplayModeOnAccessKeyInvoked(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvoked, WINRT_WRAP(void), bool);
            this->shim().ExitDisplayModeOnAccessKeyInvoked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAccessKeyScope(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScope, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAccessKeyScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAccessKeyScope(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScope, WINRT_WRAP(void), bool);
            this->shim().IsAccessKeyScope(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyScopeOwner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwner, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().AccessKeyScopeOwner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessKeyScopeOwner(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwner, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().AccessKeyScopeOwner(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKey(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessKey(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKey, WINRT_WRAP(void), hstring const&);
            this->shim().AccessKey(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContextRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ContextRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContextRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ContextRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContextRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContextRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContextRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ContextCanceled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextCanceled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::RoutedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ContextCanceled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::RoutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContextCanceled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContextCanceled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContextCanceled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AccessKeyDisplayRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyDisplayRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyDisplayRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyDisplayRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyDisplayRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AccessKeyDisplayDismissed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyDisplayDismissed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyDisplayDismissed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyDisplayDismissed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyDisplayDismissed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AccessKeyInvoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyInvoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessKeyInvoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessKeyInvoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessKeyInvoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessKeyInvoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement5> : produce_base<D, Windows::UI::Xaml::IUIElement5>
{
    int32_t WINRT_CALL get_Lights(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lights, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Media::XamlLight>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Media::XamlLight>>(this->shim().Lights());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementMode, WINRT_WRAP(Windows::UI::Xaml::Input::KeyTipPlacementMode));
            *value = detach_from<Windows::UI::Xaml::Input::KeyTipPlacementMode>(this->shim().KeyTipPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementMode, WINRT_WRAP(void), Windows::UI::Xaml::Input::KeyTipPlacementMode const&);
            this->shim().KeyTipPlacementMode(*reinterpret_cast<Windows::UI::Xaml::Input::KeyTipPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipHorizontalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyTipHorizontalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipHorizontalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffset, WINRT_WRAP(void), double);
            this->shim().KeyTipHorizontalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipVerticalOffset(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffset, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().KeyTipVerticalOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipVerticalOffset(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffset, WINRT_WRAP(void), double);
            this->shim().KeyTipVerticalOffset(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusKeyboardNavigation(Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusKeyboardNavigation, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode>(this->shim().XYFocusKeyboardNavigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusKeyboardNavigation(Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusKeyboardNavigation, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode const&);
            this->shim().XYFocusKeyboardNavigation(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusKeyboardNavigationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusUpNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusUpNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusDownNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusDownNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusLeftNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusLeftNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(Windows::UI::Xaml::Input::XYFocusNavigationStrategy));
            *value = detach_from<Windows::UI::Xaml::Input::XYFocusNavigationStrategy>(this->shim().XYFocusRightNavigationStrategy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategy, WINRT_WRAP(void), Windows::UI::Xaml::Input::XYFocusNavigationStrategy const&);
            this->shim().XYFocusRightNavigationStrategy(*reinterpret_cast<Windows::UI::Xaml::Input::XYFocusNavigationStrategy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HighContrastAdjustment(Windows::UI::Xaml::ElementHighContrastAdjustment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(Windows::UI::Xaml::ElementHighContrastAdjustment));
            *value = detach_from<Windows::UI::Xaml::ElementHighContrastAdjustment>(this->shim().HighContrastAdjustment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HighContrastAdjustment(Windows::UI::Xaml::ElementHighContrastAdjustment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustment, WINRT_WRAP(void), Windows::UI::Xaml::ElementHighContrastAdjustment const&);
            this->shim().HighContrastAdjustment(*reinterpret_cast<Windows::UI::Xaml::ElementHighContrastAdjustment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabFocusNavigation(Windows::UI::Xaml::Input::KeyboardNavigationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabFocusNavigation, WINRT_WRAP(Windows::UI::Xaml::Input::KeyboardNavigationMode));
            *value = detach_from<Windows::UI::Xaml::Input::KeyboardNavigationMode>(this->shim().TabFocusNavigation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TabFocusNavigation(Windows::UI::Xaml::Input::KeyboardNavigationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabFocusNavigation, WINRT_WRAP(void), Windows::UI::Xaml::Input::KeyboardNavigationMode const&);
            this->shim().TabFocusNavigation(*reinterpret_cast<Windows::UI::Xaml::Input::KeyboardNavigationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GettingFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GettingFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::GettingFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GettingFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::GettingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GettingFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GettingFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GettingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LosingFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LosingFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::LosingFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LosingFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::LosingFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LosingFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LosingFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LosingFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_NoFocusCandidateFound(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoFocusCandidateFound, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().NoFocusCandidateFound(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::NoFocusCandidateFoundEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NoFocusCandidateFound(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NoFocusCandidateFound, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NoFocusCandidateFound(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL StartBringIntoView() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartBringIntoView, WINRT_WRAP(void));
            this->shim().StartBringIntoView();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartBringIntoViewWithOptions(void* options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartBringIntoView, WINRT_WRAP(void), Windows::UI::Xaml::BringIntoViewOptions const&);
            this->shim().StartBringIntoView(*reinterpret_cast<Windows::UI::Xaml::BringIntoViewOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement7> : produce_base<D, Windows::UI::Xaml::IUIElement7>
{
    int32_t WINRT_CALL get_KeyboardAccelerators(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAccelerators, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Input::KeyboardAccelerator>>(this->shim().KeyboardAccelerators());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CharacterReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CharacterReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::CharacterReceivedRoutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CharacterReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CharacterReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CharacterReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ProcessKeyboardAccelerators(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessKeyboardAccelerators, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProcessKeyboardAccelerators(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProcessKeyboardAccelerators(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProcessKeyboardAccelerators, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProcessKeyboardAccelerators(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PreviewKeyDown(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewKeyDown, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::KeyEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PreviewKeyDown(*reinterpret_cast<Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PreviewKeyDown(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PreviewKeyDown, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PreviewKeyDown(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PreviewKeyUp(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewKeyUp, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Input::KeyEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PreviewKeyUp(*reinterpret_cast<Windows::UI::Xaml::Input::KeyEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PreviewKeyUp(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PreviewKeyUp, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PreviewKeyUp(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL TryInvokeKeyboardAccelerator(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryInvokeKeyboardAccelerator, WINRT_WRAP(void), Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const&);
            this->shim().TryInvokeKeyboardAccelerator(*reinterpret_cast<Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement8> : produce_base<D, Windows::UI::Xaml::IUIElement8>
{
    int32_t WINRT_CALL get_KeyTipTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().KeyTipTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyTipTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().KeyTipTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAcceleratorPlacementTarget(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementTarget, WINRT_WRAP(Windows::UI::Xaml::DependencyObject));
            *value = detach_from<Windows::UI::Xaml::DependencyObject>(this->shim().KeyboardAcceleratorPlacementTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyboardAcceleratorPlacementTarget(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementTarget, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&);
            this->shim().KeyboardAcceleratorPlacementTarget(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAcceleratorPlacementMode(Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementMode, WINRT_WRAP(Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode));
            *value = detach_from<Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode>(this->shim().KeyboardAcceleratorPlacementMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeyboardAcceleratorPlacementMode(Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementMode, WINRT_WRAP(void), Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode const&);
            this->shim().KeyboardAcceleratorPlacementMode(*reinterpret_cast<Windows::UI::Xaml::Input::KeyboardAcceleratorPlacementMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BringIntoViewRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BringIntoViewRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BringIntoViewRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::UIElement, Windows::UI::Xaml::BringIntoViewRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BringIntoViewRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BringIntoViewRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BringIntoViewRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElement9> : produce_base<D, Windows::UI::Xaml::IUIElement9>
{
    int32_t WINRT_CALL get_CanBeScrollAnchor(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanBeScrollAnchor, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanBeScrollAnchor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanBeScrollAnchor(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanBeScrollAnchor, WINRT_WRAP(void), bool);
            this->shim().CanBeScrollAnchor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpacityTransition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpacityTransition, WINRT_WRAP(Windows::UI::Xaml::ScalarTransition));
            *value = detach_from<Windows::UI::Xaml::ScalarTransition>(this->shim().OpacityTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OpacityTransition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpacityTransition, WINRT_WRAP(void), Windows::UI::Xaml::ScalarTransition const&);
            this->shim().OpacityTransition(*reinterpret_cast<Windows::UI::Xaml::ScalarTransition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Translation(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Translation, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Translation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Translation(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Translation, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Translation(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TranslationTransition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslationTransition, WINRT_WRAP(Windows::UI::Xaml::Vector3Transition));
            *value = detach_from<Windows::UI::Xaml::Vector3Transition>(this->shim().TranslationTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TranslationTransition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TranslationTransition, WINRT_WRAP(void), Windows::UI::Xaml::Vector3Transition const&);
            this->shim().TranslationTransition(*reinterpret_cast<Windows::UI::Xaml::Vector3Transition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), float);
            this->shim().Rotation(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationTransition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationTransition, WINRT_WRAP(Windows::UI::Xaml::ScalarTransition));
            *value = detach_from<Windows::UI::Xaml::ScalarTransition>(this->shim().RotationTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationTransition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationTransition, WINRT_WRAP(void), Windows::UI::Xaml::ScalarTransition const&);
            this->shim().RotationTransition(*reinterpret_cast<Windows::UI::Xaml::ScalarTransition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleTransition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleTransition, WINRT_WRAP(Windows::UI::Xaml::Vector3Transition));
            *value = detach_from<Windows::UI::Xaml::Vector3Transition>(this->shim().ScaleTransition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaleTransition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleTransition, WINRT_WRAP(void), Windows::UI::Xaml::Vector3Transition const&);
            this->shim().ScaleTransition(*reinterpret_cast<Windows::UI::Xaml::Vector3Transition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformMatrix(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().TransformMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformMatrix(Windows::Foundation::Numerics::float4x4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformMatrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float4x4 const&);
            this->shim().TransformMatrix(*reinterpret_cast<Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CenterPoint(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().CenterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CenterPoint(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterPoint, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().CenterPoint(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotationAxis(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAxis, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().RotationAxis());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotationAxis(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationAxis, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().RotationAxis(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAnimation(void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAnimation, WINRT_WRAP(void), Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().StartAnimation(*reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAnimation(void* animation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAnimation, WINRT_WRAP(void), Windows::UI::Composition::ICompositionAnimationBase const&);
            this->shim().StopAnimation(*reinterpret_cast<Windows::UI::Composition::ICompositionAnimationBase const*>(&animation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementFactory> : produce_base<D, Windows::UI::Xaml::IUIElementFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementOverrides> : produce_base<D, Windows::UI::Xaml::IUIElementOverrides>
{
    int32_t WINRT_CALL OnCreateAutomationPeer(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnCreateAutomationPeer, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().OnCreateAutomationPeer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnDisconnectVisualChildren() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnDisconnectVisualChildren, WINRT_WRAP(void));
            this->shim().OnDisconnectVisualChildren();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindSubElementsForTouchTargeting(Windows::Foundation::Point point, Windows::Foundation::Rect boundingRect, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindSubElementsForTouchTargeting, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>>), Windows::Foundation::Point const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>>>(this->shim().FindSubElementsForTouchTargeting(*reinterpret_cast<Windows::Foundation::Point const*>(&point), *reinterpret_cast<Windows::Foundation::Rect const*>(&boundingRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementOverrides7> : produce_base<D, Windows::UI::Xaml::IUIElementOverrides7>
{
    int32_t WINRT_CALL GetChildrenInTabFocusOrder(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChildrenInTabFocusOrder, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject>));
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject>>(this->shim().GetChildrenInTabFocusOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnProcessKeyboardAccelerators(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnProcessKeyboardAccelerators, WINRT_WRAP(void), Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const&);
            this->shim().OnProcessKeyboardAccelerators(*reinterpret_cast<Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementOverrides8> : produce_base<D, Windows::UI::Xaml::IUIElementOverrides8>
{
    int32_t WINRT_CALL OnKeyboardAcceleratorInvoked(void* args) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnKeyboardAcceleratorInvoked, WINRT_WRAP(void), Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const&);
            this->shim().OnKeyboardAcceleratorInvoked(*reinterpret_cast<Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const*>(&args));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnBringIntoViewRequested(void* e) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnBringIntoViewRequested, WINRT_WRAP(void), Windows::UI::Xaml::BringIntoViewRequestedEventArgs const&);
            this->shim().OnBringIntoViewRequested(*reinterpret_cast<Windows::UI::Xaml::BringIntoViewRequestedEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementOverrides9> : produce_base<D, Windows::UI::Xaml::IUIElementOverrides9>
{
    int32_t WINRT_CALL PopulatePropertyInfoOverride(void* propertyName, void* animationPropertyInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulatePropertyInfoOverride, WINRT_WRAP(void), hstring const&, Windows::UI::Composition::AnimationPropertyInfo const&);
            this->shim().PopulatePropertyInfoOverride(*reinterpret_cast<hstring const*>(&propertyName), *reinterpret_cast<Windows::UI::Composition::AnimationPropertyInfo const*>(&animationPropertyInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics> : produce_base<D, Windows::UI::Xaml::IUIElementStatics>
{
    int32_t WINRT_CALL get_KeyDownEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyDownEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().KeyDownEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyUpEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyUpEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().KeyUpEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerEnteredEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerEnteredEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerEnteredEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerPressedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerPressedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerPressedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerMovedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerMovedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerMovedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerReleasedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerReleasedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerReleasedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerExitedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerExitedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerExitedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCaptureLostEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCaptureLostEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerCaptureLostEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCanceledEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCanceledEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerCanceledEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerWheelChangedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerWheelChangedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PointerWheelChangedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TappedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TappedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().TappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DoubleTappedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoubleTappedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().DoubleTappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HoldingEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldingEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().HoldingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightTappedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightTappedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().RightTappedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationStartingEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStartingEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationStartingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationInertiaStartingEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationInertiaStartingEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationInertiaStartingEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationStartedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationStartedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationStartedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationDeltaEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationDeltaEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationDeltaEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationCompletedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationCompletedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ManipulationCompletedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragEnterEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragEnterEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().DragEnterEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragLeaveEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragLeaveEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().DragLeaveEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DragOverEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DragOverEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().DragOverEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().DropEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowDropProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowDropProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AllowDropProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OpacityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpacityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().OpacityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClipProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClipProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ClipProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderTransformProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransformProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RenderTransformProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProjectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProjectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ProjectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RenderTransformOriginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderTransformOriginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RenderTransformOriginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHitTestVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHitTestVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsHitTestVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibilityProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibilityProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VisibilityProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UseLayoutRoundingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseLayoutRoundingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().UseLayoutRoundingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitionsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitionsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransitionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CacheModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CacheModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTapEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTapEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDoubleTapEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDoubleTapEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsDoubleTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRightTapEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRightTapEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsRightTapEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHoldingEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHoldingEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsHoldingEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManipulationModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManipulationModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ManipulationModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointerCapturesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerCapturesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PointerCapturesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics10> : produce_base<D, Windows::UI::Xaml::IUIElementStatics10>
{
    int32_t WINRT_CALL get_ShadowProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShadowProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ShadowProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics2> : produce_base<D, Windows::UI::Xaml::IUIElementStatics2>
{
    int32_t WINRT_CALL get_CompositeModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CompositeModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics3> : produce_base<D, Windows::UI::Xaml::IUIElementStatics3>
{
    int32_t WINRT_CALL get_Transform3DProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transform3DProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Transform3DProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDragProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDragProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanDragProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryStartDirectManipulation(void* value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryStartDirectManipulation, WINRT_WRAP(bool), Windows::UI::Xaml::Input::Pointer const&);
            *result = detach_from<bool>(this->shim().TryStartDirectManipulation(*reinterpret_cast<Windows::UI::Xaml::Input::Pointer const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics4> : produce_base<D, Windows::UI::Xaml::IUIElementStatics4>
{
    int32_t WINRT_CALL get_ContextFlyoutProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextFlyoutProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ContextFlyoutProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvokedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDisplayModeOnAccessKeyInvokedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ExitDisplayModeOnAccessKeyInvokedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAccessKeyScopeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccessKeyScopeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsAccessKeyScopeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyScopeOwnerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyScopeOwnerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyScopeOwnerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessKeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessKeyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics5> : produce_base<D, Windows::UI::Xaml::IUIElementStatics5>
{
    int32_t WINRT_CALL get_LightsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LightsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipPlacementModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipPlacementModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipHorizontalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipHorizontalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipHorizontalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipVerticalOffsetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipVerticalOffsetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipVerticalOffsetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusKeyboardNavigationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusKeyboardNavigationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusKeyboardNavigationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusUpNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusUpNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusUpNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusDownNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusDownNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusDownNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusLeftNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusLeftNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XYFocusRightNavigationStrategyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusRightNavigationStrategyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().XYFocusRightNavigationStrategyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HighContrastAdjustmentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighContrastAdjustmentProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HighContrastAdjustmentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabFocusNavigationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabFocusNavigationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TabFocusNavigationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics6> : produce_base<D, Windows::UI::Xaml::IUIElementStatics6>
{
    int32_t WINRT_CALL get_GettingFocusEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GettingFocusEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().GettingFocusEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LosingFocusEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LosingFocusEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().LosingFocusEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NoFocusCandidateFoundEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoFocusCandidateFoundEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().NoFocusCandidateFoundEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics7> : produce_base<D, Windows::UI::Xaml::IUIElementStatics7>
{
    int32_t WINRT_CALL get_PreviewKeyDownEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewKeyDownEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PreviewKeyDownEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterReceivedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterReceivedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().CharacterReceivedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviewKeyUpEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewKeyUpEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().PreviewKeyUpEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics8> : produce_base<D, Windows::UI::Xaml::IUIElementStatics8>
{
    int32_t WINRT_CALL get_BringIntoViewRequestedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BringIntoViewRequestedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().BringIntoViewRequestedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContextRequestedEvent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContextRequestedEvent, WINRT_WRAP(Windows::UI::Xaml::RoutedEvent));
            *value = detach_from<Windows::UI::Xaml::RoutedEvent>(this->shim().ContextRequestedEvent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyTipTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyTipTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyTipTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAcceleratorPlacementTargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementTargetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorPlacementTargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyboardAcceleratorPlacementModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardAcceleratorPlacementModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().KeyboardAcceleratorPlacementModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAsScrollPort(void* element) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAsScrollPort, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().RegisterAsScrollPort(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementStatics9> : produce_base<D, Windows::UI::Xaml::IUIElementStatics9>
{
    int32_t WINRT_CALL get_CanBeScrollAnchorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanBeScrollAnchorProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanBeScrollAnchorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementWeakCollection> : produce_base<D, Windows::UI::Xaml::IUIElementWeakCollection>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUIElementWeakCollectionFactory> : produce_base<D, Windows::UI::Xaml::IUIElementWeakCollectionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::UIElementWeakCollection), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::UIElementWeakCollection>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IUnhandledExceptionEventArgs> : produce_base<D, Windows::UI::Xaml::IUnhandledExceptionEventArgs>
{
    int32_t WINRT_CALL get_Exception(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exception, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().Exception());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
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
struct produce<D, Windows::UI::Xaml::IVector3Transition> : produce_base<D, Windows::UI::Xaml::IVector3Transition>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Components(Windows::UI::Xaml::Vector3TransitionComponents* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(Windows::UI::Xaml::Vector3TransitionComponents));
            *value = detach_from<Windows::UI::Xaml::Vector3TransitionComponents>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Components(Windows::UI::Xaml::Vector3TransitionComponents value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(void), Windows::UI::Xaml::Vector3TransitionComponents const&);
            this->shim().Components(*reinterpret_cast<Windows::UI::Xaml::Vector3TransitionComponents const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVector3TransitionFactory> : produce_base<D, Windows::UI::Xaml::IVector3TransitionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Vector3Transition), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Vector3Transition>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualState> : produce_base<D, Windows::UI::Xaml::IVisualState>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Storyboard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::Storyboard));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Storyboard(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Storyboard const&);
            this->shim().Storyboard(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualState2> : produce_base<D, Windows::UI::Xaml::IVisualState2>
{
    int32_t WINRT_CALL get_Setters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Setters, WINRT_WRAP(Windows::UI::Xaml::SetterBaseCollection));
            *value = detach_from<Windows::UI::Xaml::SetterBaseCollection>(this->shim().Setters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StateTriggers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateTriggers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::StateTriggerBase>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::StateTriggerBase>>(this->shim().StateTriggers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateChangedEventArgs> : produce_base<D, Windows::UI::Xaml::IVisualStateChangedEventArgs>
{
    int32_t WINRT_CALL get_OldState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldState, WINRT_WRAP(Windows::UI::Xaml::VisualState));
            *value = detach_from<Windows::UI::Xaml::VisualState>(this->shim().OldState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OldState(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldState, WINRT_WRAP(void), Windows::UI::Xaml::VisualState const&);
            this->shim().OldState(*reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewState, WINRT_WRAP(Windows::UI::Xaml::VisualState));
            *value = detach_from<Windows::UI::Xaml::VisualState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NewState(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewState, WINRT_WRAP(void), Windows::UI::Xaml::VisualState const&);
            this->shim().NewState(*reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Control(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(Windows::UI::Xaml::Controls::Control));
            *value = detach_from<Windows::UI::Xaml::Controls::Control>(this->shim().Control());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Control(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Control, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Control const&);
            this->shim().Control(*reinterpret_cast<Windows::UI::Xaml::Controls::Control const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateGroup> : produce_base<D, Windows::UI::Xaml::IVisualStateGroup>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transitions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualTransition>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualTransition>>(this->shim().Transitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_States(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(States, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualState>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualState>>(this->shim().States());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentState, WINRT_WRAP(Windows::UI::Xaml::VisualState));
            *value = detach_from<Windows::UI::Xaml::VisualState>(this->shim().CurrentState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CurrentStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentStateChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::VisualStateChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanged(*reinterpret_cast<Windows::UI::Xaml::VisualStateChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CurrentStateChanging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentStateChanging, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::VisualStateChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentStateChanging(*reinterpret_cast<Windows::UI::Xaml::VisualStateChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentStateChanging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentStateChanging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentStateChanging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateManager> : produce_base<D, Windows::UI::Xaml::IVisualStateManager>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateManagerFactory> : produce_base<D, Windows::UI::Xaml::IVisualStateManagerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::VisualStateManager), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::VisualStateManager>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateManagerOverrides> : produce_base<D, Windows::UI::Xaml::IVisualStateManagerOverrides>
{
    int32_t WINRT_CALL GoToStateCore(void* control, void* templateRoot, void* stateName, void* group, void* state, bool useTransitions, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoToStateCore, WINRT_WRAP(bool), Windows::UI::Xaml::Controls::Control const&, Windows::UI::Xaml::FrameworkElement const&, hstring const&, Windows::UI::Xaml::VisualStateGroup const&, Windows::UI::Xaml::VisualState const&, bool);
            *result = detach_from<bool>(this->shim().GoToStateCore(*reinterpret_cast<Windows::UI::Xaml::Controls::Control const*>(&control), *reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&templateRoot), *reinterpret_cast<hstring const*>(&stateName), *reinterpret_cast<Windows::UI::Xaml::VisualStateGroup const*>(&group), *reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&state), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateManagerProtected> : produce_base<D, Windows::UI::Xaml::IVisualStateManagerProtected>
{
    int32_t WINRT_CALL RaiseCurrentStateChanging(void* stateGroup, void* oldState, void* newState, void* control) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseCurrentStateChanging, WINRT_WRAP(void), Windows::UI::Xaml::VisualStateGroup const&, Windows::UI::Xaml::VisualState const&, Windows::UI::Xaml::VisualState const&, Windows::UI::Xaml::Controls::Control const&);
            this->shim().RaiseCurrentStateChanging(*reinterpret_cast<Windows::UI::Xaml::VisualStateGroup const*>(&stateGroup), *reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&oldState), *reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&newState), *reinterpret_cast<Windows::UI::Xaml::Controls::Control const*>(&control));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RaiseCurrentStateChanged(void* stateGroup, void* oldState, void* newState, void* control) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseCurrentStateChanged, WINRT_WRAP(void), Windows::UI::Xaml::VisualStateGroup const&, Windows::UI::Xaml::VisualState const&, Windows::UI::Xaml::VisualState const&, Windows::UI::Xaml::Controls::Control const&);
            this->shim().RaiseCurrentStateChanged(*reinterpret_cast<Windows::UI::Xaml::VisualStateGroup const*>(&stateGroup), *reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&oldState), *reinterpret_cast<Windows::UI::Xaml::VisualState const*>(&newState), *reinterpret_cast<Windows::UI::Xaml::Controls::Control const*>(&control));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualStateManagerStatics> : produce_base<D, Windows::UI::Xaml::IVisualStateManagerStatics>
{
    int32_t WINRT_CALL GetVisualStateGroups(void* obj, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVisualStateGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualStateGroup>), Windows::UI::Xaml::FrameworkElement const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualStateGroup>>(this->shim().GetVisualStateGroups(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&obj)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVisualStateManagerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVisualStateManagerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CustomVisualStateManagerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCustomVisualStateManager(void* obj, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomVisualStateManager, WINRT_WRAP(Windows::UI::Xaml::VisualStateManager), Windows::UI::Xaml::FrameworkElement const&);
            *result = detach_from<Windows::UI::Xaml::VisualStateManager>(this->shim().GetCustomVisualStateManager(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&obj)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCustomVisualStateManager(void* obj, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCustomVisualStateManager, WINRT_WRAP(void), Windows::UI::Xaml::FrameworkElement const&, Windows::UI::Xaml::VisualStateManager const&);
            this->shim().SetCustomVisualStateManager(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&obj), *reinterpret_cast<Windows::UI::Xaml::VisualStateManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GoToState(void* control, void* stateName, bool useTransitions, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoToState, WINRT_WRAP(bool), Windows::UI::Xaml::Controls::Control const&, hstring const&, bool);
            *result = detach_from<bool>(this->shim().GoToState(*reinterpret_cast<Windows::UI::Xaml::Controls::Control const*>(&control), *reinterpret_cast<hstring const*>(&stateName), useTransitions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualTransition> : produce_base<D, Windows::UI::Xaml::IVisualTransition>
{
    int32_t WINRT_CALL get_GeneratedDuration(struct struct_Windows_UI_Xaml_Duration* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedDuration, WINRT_WRAP(Windows::UI::Xaml::Duration));
            *value = detach_from<Windows::UI::Xaml::Duration>(this->shim().GeneratedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GeneratedDuration(struct struct_Windows_UI_Xaml_Duration value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedDuration, WINRT_WRAP(void), Windows::UI::Xaml::Duration const&);
            this->shim().GeneratedDuration(*reinterpret_cast<Windows::UI::Xaml::Duration const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeneratedEasingFunction(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedEasingFunction, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::EasingFunctionBase));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::EasingFunctionBase>(this->shim().GeneratedEasingFunction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GeneratedEasingFunction(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedEasingFunction, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::EasingFunctionBase const&);
            this->shim().GeneratedEasingFunction(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::EasingFunctionBase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_To(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(void), hstring const&);
            this->shim().To(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), hstring const&);
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Storyboard(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(Windows::UI::Xaml::Media::Animation::Storyboard));
            *value = detach_from<Windows::UI::Xaml::Media::Animation::Storyboard>(this->shim().Storyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Storyboard(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Storyboard, WINRT_WRAP(void), Windows::UI::Xaml::Media::Animation::Storyboard const&);
            this->shim().Storyboard(*reinterpret_cast<Windows::UI::Xaml::Media::Animation::Storyboard const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IVisualTransitionFactory> : produce_base<D, Windows::UI::Xaml::IVisualTransitionFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::VisualTransition), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::VisualTransition>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IWindow> : produce_base<D, Windows::UI::Xaml::IWindow>
{
    int32_t WINRT_CALL get_Bounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL add_Activated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activated, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::WindowActivatedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Activated(*reinterpret_cast<Windows::UI::Xaml::WindowActivatedEventHandler const*>(&handler)));
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

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::WindowClosedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::UI::Xaml::WindowClosedEventHandler const*>(&handler)));
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

    int32_t WINRT_CALL add_SizeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::WindowSizeChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().SizeChanged(*reinterpret_cast<Windows::UI::Xaml::WindowSizeChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SizeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SizeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SizeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VisibilityChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::WindowVisibilityChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<Windows::UI::Xaml::WindowVisibilityChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisibilityChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Activate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activate, WINRT_WRAP(void));
            this->shim().Activate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IWindow2> : produce_base<D, Windows::UI::Xaml::IWindow2>
{
    int32_t WINRT_CALL SetTitleBar(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTitleBar, WINRT_WRAP(void), Windows::UI::Xaml::UIElement const&);
            this->shim().SetTitleBar(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IWindow3> : produce_base<D, Windows::UI::Xaml::IWindow3>
{
    int32_t WINRT_CALL get_Compositor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compositor, WINRT_WRAP(Windows::UI::Composition::Compositor));
            *value = detach_from<Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IWindow4> : produce_base<D, Windows::UI::Xaml::IWindow4>
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
struct produce<D, Windows::UI::Xaml::IWindowCreatedEventArgs> : produce_base<D, Windows::UI::Xaml::IWindowCreatedEventArgs>
{
    int32_t WINRT_CALL get_Window(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Window, WINRT_WRAP(Windows::UI::Xaml::Window));
            *value = detach_from<Windows::UI::Xaml::Window>(this->shim().Window());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IWindowStatics> : produce_base<D, Windows::UI::Xaml::IWindowStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::UI::Xaml::Window));
            *value = detach_from<Windows::UI::Xaml::Window>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::IXamlRoot> : produce_base<D, Windows::UI::Xaml::IXamlRoot>
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

    int32_t WINRT_CALL get_RasterizationScale(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizationScale, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RasterizationScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHostVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHostVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHostVisible());
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

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::XamlRoot, Windows::UI::Xaml::XamlRootChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::XamlRoot, Windows::UI::Xaml::XamlRootChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::UI::Xaml::IXamlRootChangedEventArgs> : produce_base<D, Windows::UI::Xaml::IXamlRootChangedEventArgs>
{};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IApplicationOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IApplicationOverrides>
{
    void OnActivated(Windows::ApplicationModel::Activation::IActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnActivated(args);
        }
        return this->shim().OnActivated(args);
    }
    void OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnLaunched(args);
        }
        return this->shim().OnLaunched(args);
    }
    void OnFileActivated(Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnFileActivated(args);
        }
        return this->shim().OnFileActivated(args);
    }
    void OnSearchActivated(Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnSearchActivated(args);
        }
        return this->shim().OnSearchActivated(args);
    }
    void OnShareTargetActivated(Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnShareTargetActivated(args);
        }
        return this->shim().OnShareTargetActivated(args);
    }
    void OnFileOpenPickerActivated(Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnFileOpenPickerActivated(args);
        }
        return this->shim().OnFileOpenPickerActivated(args);
    }
    void OnFileSavePickerActivated(Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnFileSavePickerActivated(args);
        }
        return this->shim().OnFileSavePickerActivated(args);
    }
    void OnCachedFileUpdaterActivated(Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnCachedFileUpdaterActivated(args);
        }
        return this->shim().OnCachedFileUpdaterActivated(args);
    }
    void OnWindowCreated(Windows::UI::Xaml::WindowCreatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnWindowCreated(args);
        }
        return this->shim().OnWindowCreated(args);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IApplicationOverrides2>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IApplicationOverrides2>
{
    void OnBackgroundActivated(Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args)
    {
        Windows::UI::Xaml::IApplicationOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnBackgroundActivated(args);
        }
        return this->shim().OnBackgroundActivated(args);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IFrameworkElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IFrameworkElementOverrides>
{
    Windows::Foundation::Size MeasureOverride(Windows::Foundation::Size const& availableSize)
    {
        Windows::UI::Xaml::IFrameworkElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.MeasureOverride(availableSize);
        }
        return this->shim().MeasureOverride(availableSize);
    }
    Windows::Foundation::Size ArrangeOverride(Windows::Foundation::Size const& finalSize)
    {
        Windows::UI::Xaml::IFrameworkElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.ArrangeOverride(finalSize);
        }
        return this->shim().ArrangeOverride(finalSize);
    }
    void OnApplyTemplate()
    {
        Windows::UI::Xaml::IFrameworkElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnApplyTemplate();
        }
        return this->shim().OnApplyTemplate();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IFrameworkElementOverrides2>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IFrameworkElementOverrides2>
{
    bool GoToElementStateCore(hstring const& stateName, bool useTransitions)
    {
        Windows::UI::Xaml::IFrameworkElementOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GoToElementStateCore(stateName, useTransitions);
        }
        return this->shim().GoToElementStateCore(stateName, useTransitions);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IUIElementOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IUIElementOverrides>
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer OnCreateAutomationPeer()
    {
        Windows::UI::Xaml::IUIElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnCreateAutomationPeer();
        }
        return this->shim().OnCreateAutomationPeer();
    }
    void OnDisconnectVisualChildren()
    {
        Windows::UI::Xaml::IUIElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnDisconnectVisualChildren();
        }
        return this->shim().OnDisconnectVisualChildren();
    }
    Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>> FindSubElementsForTouchTargeting(Windows::Foundation::Point const& point, Windows::Foundation::Rect const& boundingRect)
    {
        Windows::UI::Xaml::IUIElementOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.FindSubElementsForTouchTargeting(point, boundingRect);
        }
        return this->shim().FindSubElementsForTouchTargeting(point, boundingRect);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IUIElementOverrides7>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IUIElementOverrides7>
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject> GetChildrenInTabFocusOrder()
    {
        Windows::UI::Xaml::IUIElementOverrides7 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetChildrenInTabFocusOrder();
        }
        return this->shim().GetChildrenInTabFocusOrder();
    }
    void OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args)
    {
        Windows::UI::Xaml::IUIElementOverrides7 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnProcessKeyboardAccelerators(args);
        }
        return this->shim().OnProcessKeyboardAccelerators(args);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IUIElementOverrides8>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IUIElementOverrides8>
{
    void OnKeyboardAcceleratorInvoked(Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args)
    {
        Windows::UI::Xaml::IUIElementOverrides8 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnKeyboardAcceleratorInvoked(args);
        }
        return this->shim().OnKeyboardAcceleratorInvoked(args);
    }
    void OnBringIntoViewRequested(Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e)
    {
        Windows::UI::Xaml::IUIElementOverrides8 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnBringIntoViewRequested(e);
        }
        return this->shim().OnBringIntoViewRequested(e);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IUIElementOverrides9>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IUIElementOverrides9>
{
    void PopulatePropertyInfoOverride(hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo)
    {
        Windows::UI::Xaml::IUIElementOverrides9 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
        }
        return this->shim().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::IVisualStateManagerOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::IVisualStateManagerOverrides>
{
    bool GoToStateCore(Windows::UI::Xaml::Controls::Control const& control, Windows::UI::Xaml::FrameworkElement const& templateRoot, hstring const& stateName, Windows::UI::Xaml::VisualStateGroup const& group, Windows::UI::Xaml::VisualState const& state, bool useTransitions)
    {
        Windows::UI::Xaml::IVisualStateManagerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
        }
        return this->shim().GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

inline AdaptiveTrigger::AdaptiveTrigger()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<AdaptiveTrigger, Windows::UI::Xaml::IAdaptiveTriggerFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty AdaptiveTrigger::MinWindowWidthProperty()
{
    return impl::call_factory<AdaptiveTrigger, Windows::UI::Xaml::IAdaptiveTriggerStatics>([&](auto&& f) { return f.MinWindowWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AdaptiveTrigger::MinWindowHeightProperty()
{
    return impl::call_factory<AdaptiveTrigger, Windows::UI::Xaml::IAdaptiveTriggerStatics>([&](auto&& f) { return f.MinWindowHeightProperty(); });
}

inline Application::Application()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<Application, Windows::UI::Xaml::IApplicationFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Application Application::Current()
{
    return impl::call_factory<Application, Windows::UI::Xaml::IApplicationStatics>([&](auto&& f) { return f.Current(); });
}

inline void Application::Start(Windows::UI::Xaml::ApplicationInitializationCallback const& callback)
{
    impl::call_factory<Application, Windows::UI::Xaml::IApplicationStatics>([&](auto&& f) { return f.Start(callback); });
}

inline void Application::LoadComponent(Windows::Foundation::IInspectable const& component, Windows::Foundation::Uri const& resourceLocator)
{
    impl::call_factory<Application, Windows::UI::Xaml::IApplicationStatics>([&](auto&& f) { return f.LoadComponent(component, resourceLocator); });
}

inline void Application::LoadComponent(Windows::Foundation::IInspectable const& component, Windows::Foundation::Uri const& resourceLocator, Windows::UI::Xaml::Controls::Primitives::ComponentResourceLocation const& componentResourceLocation)
{
    impl::call_factory<Application, Windows::UI::Xaml::IApplicationStatics>([&](auto&& f) { return f.LoadComponent(component, resourceLocator, componentResourceLocation); });
}

inline BringIntoViewOptions::BringIntoViewOptions() :
    BringIntoViewOptions(impl::call_factory<BringIntoViewOptions>([](auto&& f) { return f.template ActivateInstance<BringIntoViewOptions>(); }))
{}

inline BrushTransition::BrushTransition()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<BrushTransition, Windows::UI::Xaml::IBrushTransitionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline ColorPaletteResources::ColorPaletteResources()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ColorPaletteResources, Windows::UI::Xaml::IColorPaletteResourcesFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::CornerRadius CornerRadiusHelper::FromRadii(double topLeft, double topRight, double bottomRight, double bottomLeft)
{
    return impl::call_factory<CornerRadiusHelper, Windows::UI::Xaml::ICornerRadiusHelperStatics>([&](auto&& f) { return f.FromRadii(topLeft, topRight, bottomRight, bottomLeft); });
}

inline Windows::UI::Xaml::CornerRadius CornerRadiusHelper::FromUniformRadius(double uniformRadius)
{
    return impl::call_factory<CornerRadiusHelper, Windows::UI::Xaml::ICornerRadiusHelperStatics>([&](auto&& f) { return f.FromUniformRadius(uniformRadius); });
}

inline DataTemplate::DataTemplate()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DataTemplate, Windows::UI::Xaml::IDataTemplateFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty DataTemplate::ExtensionInstanceProperty()
{
    return impl::call_factory<DataTemplate, Windows::UI::Xaml::IDataTemplateStatics2>([&](auto&& f) { return f.ExtensionInstanceProperty(); });
}

inline Windows::UI::Xaml::IDataTemplateExtension DataTemplate::GetExtensionInstance(Windows::UI::Xaml::FrameworkElement const& element)
{
    return impl::call_factory<DataTemplate, Windows::UI::Xaml::IDataTemplateStatics2>([&](auto&& f) { return f.GetExtensionInstance(element); });
}

inline void DataTemplate::SetExtensionInstance(Windows::UI::Xaml::FrameworkElement const& element, Windows::UI::Xaml::IDataTemplateExtension const& value)
{
    impl::call_factory<DataTemplate, Windows::UI::Xaml::IDataTemplateStatics2>([&](auto&& f) { return f.SetExtensionInstance(element, value); });
}

inline DataTemplateKey::DataTemplateKey()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DataTemplateKey, Windows::UI::Xaml::IDataTemplateKeyFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline DataTemplateKey::DataTemplateKey(Windows::Foundation::IInspectable const& dataType)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DataTemplateKey, Windows::UI::Xaml::IDataTemplateKeyFactory>([&](auto&& f) { return f.CreateInstanceWithType(dataType, baseInterface, innerInterface); });
}

inline DependencyObjectCollection::DependencyObjectCollection()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DependencyObjectCollection, Windows::UI::Xaml::IDependencyObjectCollectionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::Foundation::IInspectable DependencyProperty::UnsetValue()
{
    return impl::call_factory<DependencyProperty, Windows::UI::Xaml::IDependencyPropertyStatics>([&](auto&& f) { return f.UnsetValue(); });
}

inline Windows::UI::Xaml::DependencyProperty DependencyProperty::Register(param::hstring const& name, Windows::UI::Xaml::Interop::TypeName const& propertyType, Windows::UI::Xaml::Interop::TypeName const& ownerType, Windows::UI::Xaml::PropertyMetadata const& typeMetadata)
{
    return impl::call_factory<DependencyProperty, Windows::UI::Xaml::IDependencyPropertyStatics>([&](auto&& f) { return f.Register(name, propertyType, ownerType, typeMetadata); });
}

inline Windows::UI::Xaml::DependencyProperty DependencyProperty::RegisterAttached(param::hstring const& name, Windows::UI::Xaml::Interop::TypeName const& propertyType, Windows::UI::Xaml::Interop::TypeName const& ownerType, Windows::UI::Xaml::PropertyMetadata const& defaultMetadata)
{
    return impl::call_factory<DependencyProperty, Windows::UI::Xaml::IDependencyPropertyStatics>([&](auto&& f) { return f.RegisterAttached(name, propertyType, ownerType, defaultMetadata); });
}

inline DispatcherTimer::DispatcherTimer()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DispatcherTimer, Windows::UI::Xaml::IDispatcherTimerFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Duration DurationHelper::Automatic()
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Automatic(); });
}

inline Windows::UI::Xaml::Duration DurationHelper::Forever()
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Forever(); });
}

inline int32_t DurationHelper::Compare(Windows::UI::Xaml::Duration const& duration1, Windows::UI::Xaml::Duration const& duration2)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Compare(duration1, duration2); });
}

inline Windows::UI::Xaml::Duration DurationHelper::FromTimeSpan(Windows::Foundation::TimeSpan const& timeSpan)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.FromTimeSpan(timeSpan); });
}

inline bool DurationHelper::GetHasTimeSpan(Windows::UI::Xaml::Duration const& target)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.GetHasTimeSpan(target); });
}

inline Windows::UI::Xaml::Duration DurationHelper::Add(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& duration)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Add(target, duration); });
}

inline bool DurationHelper::Equals(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& value)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline Windows::UI::Xaml::Duration DurationHelper::Subtract(Windows::UI::Xaml::Duration const& target, Windows::UI::Xaml::Duration const& duration)
{
    return impl::call_factory<DurationHelper, Windows::UI::Xaml::IDurationHelperStatics>([&](auto&& f) { return f.Subtract(target, duration); });
}

inline ElementFactoryGetArgs::ElementFactoryGetArgs()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ElementFactoryGetArgs, Windows::UI::Xaml::IElementFactoryGetArgsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline ElementFactoryRecycleArgs::ElementFactoryRecycleArgs()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ElementFactoryRecycleArgs, Windows::UI::Xaml::IElementFactoryRecycleArgsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline double ElementSoundPlayer::Volume()
{
    return impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics>([&](auto&& f) { return f.Volume(); });
}

inline void ElementSoundPlayer::Volume(double value)
{
    impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics>([&](auto&& f) { return f.Volume(value); });
}

inline Windows::UI::Xaml::ElementSoundPlayerState ElementSoundPlayer::State()
{
    return impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics>([&](auto&& f) { return f.State(); });
}

inline void ElementSoundPlayer::State(Windows::UI::Xaml::ElementSoundPlayerState const& value)
{
    impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics>([&](auto&& f) { return f.State(value); });
}

inline void ElementSoundPlayer::Play(Windows::UI::Xaml::ElementSoundKind const& sound)
{
    impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics>([&](auto&& f) { return f.Play(sound); });
}

inline Windows::UI::Xaml::ElementSpatialAudioMode ElementSoundPlayer::SpatialAudioMode()
{
    return impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics2>([&](auto&& f) { return f.SpatialAudioMode(); });
}

inline void ElementSoundPlayer::SpatialAudioMode(Windows::UI::Xaml::ElementSpatialAudioMode const& value)
{
    impl::call_factory<ElementSoundPlayer, Windows::UI::Xaml::IElementSoundPlayerStatics2>([&](auto&& f) { return f.SpatialAudioMode(value); });
}

inline EventTrigger::EventTrigger() :
    EventTrigger(impl::call_factory<EventTrigger>([](auto&& f) { return f.template ActivateInstance<EventTrigger>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::TagProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.TagProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::LanguageProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.LanguageProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::ActualWidthProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.ActualWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::ActualHeightProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.ActualHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::WidthProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.WidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::HeightProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.HeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::MinWidthProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.MinWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::MaxWidthProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.MaxWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::MinHeightProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.MinHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::MaxHeightProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.MaxHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::HorizontalAlignmentProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.HorizontalAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::VerticalAlignmentProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.VerticalAlignmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::MarginProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.MarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::NameProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.NameProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::DataContextProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.DataContextProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::StyleProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.StyleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FlowDirectionProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics>([&](auto&& f) { return f.FlowDirectionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::RequestedThemeProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics2>([&](auto&& f) { return f.RequestedThemeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::AllowFocusOnInteractionProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.AllowFocusOnInteractionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FocusVisualMarginProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.FocusVisualMarginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FocusVisualSecondaryThicknessProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.FocusVisualSecondaryThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FocusVisualPrimaryThicknessProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.FocusVisualPrimaryThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FocusVisualSecondaryBrushProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.FocusVisualSecondaryBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::FocusVisualPrimaryBrushProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.FocusVisualPrimaryBrushProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::AllowFocusWhenDisabledProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics4>([&](auto&& f) { return f.AllowFocusWhenDisabledProperty(); });
}

inline void FrameworkElement::DeferTree(Windows::UI::Xaml::DependencyObject const& element)
{
    impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics5>([&](auto&& f) { return f.DeferTree(element); });
}

inline Windows::UI::Xaml::DependencyProperty FrameworkElement::ActualThemeProperty()
{
    return impl::call_factory<FrameworkElement, Windows::UI::Xaml::IFrameworkElementStatics6>([&](auto&& f) { return f.ActualThemeProperty(); });
}

inline FrameworkView::FrameworkView() :
    FrameworkView(impl::call_factory<FrameworkView>([](auto&& f) { return f.template ActivateInstance<FrameworkView>(); }))
{}

inline FrameworkViewSource::FrameworkViewSource() :
    FrameworkViewSource(impl::call_factory<FrameworkViewSource>([](auto&& f) { return f.template ActivateInstance<FrameworkViewSource>(); }))
{}

inline Windows::UI::Xaml::GridLength GridLengthHelper::Auto()
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.Auto(); });
}

inline Windows::UI::Xaml::GridLength GridLengthHelper::FromPixels(double pixels)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.FromPixels(pixels); });
}

inline Windows::UI::Xaml::GridLength GridLengthHelper::FromValueAndType(double value, Windows::UI::Xaml::GridUnitType const& type)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.FromValueAndType(value, type); });
}

inline bool GridLengthHelper::GetIsAbsolute(Windows::UI::Xaml::GridLength const& target)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.GetIsAbsolute(target); });
}

inline bool GridLengthHelper::GetIsAuto(Windows::UI::Xaml::GridLength const& target)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.GetIsAuto(target); });
}

inline bool GridLengthHelper::GetIsStar(Windows::UI::Xaml::GridLength const& target)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.GetIsStar(target); });
}

inline bool GridLengthHelper::Equals(Windows::UI::Xaml::GridLength const& target, Windows::UI::Xaml::GridLength const& value)
{
    return impl::call_factory<GridLengthHelper, Windows::UI::Xaml::IGridLengthHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline Windows::Foundation::Point PointHelper::FromCoordinates(float x, float y)
{
    return impl::call_factory<PointHelper, Windows::UI::Xaml::IPointHelperStatics>([&](auto&& f) { return f.FromCoordinates(x, y); });
}

inline PropertyMetadata::PropertyMetadata(Windows::Foundation::IInspectable const& defaultValue)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataFactory>([&](auto&& f) { return f.CreateInstanceWithDefaultValue(defaultValue, baseInterface, innerInterface); });
}

inline PropertyMetadata::PropertyMetadata(Windows::Foundation::IInspectable const& defaultValue, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataFactory>([&](auto&& f) { return f.CreateInstanceWithDefaultValueAndCallback(defaultValue, propertyChangedCallback, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::PropertyMetadata PropertyMetadata::Create(Windows::Foundation::IInspectable const& defaultValue)
{
    return impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataStatics>([&](auto&& f) { return f.Create(defaultValue); });
}

inline Windows::UI::Xaml::PropertyMetadata PropertyMetadata::Create(Windows::Foundation::IInspectable const& defaultValue, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
{
    return impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataStatics>([&](auto&& f) { return f.Create(defaultValue, propertyChangedCallback); });
}

inline Windows::UI::Xaml::PropertyMetadata PropertyMetadata::Create(Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback)
{
    return impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataStatics>([&](auto&& f) { return f.Create(createDefaultValueCallback); });
}

inline Windows::UI::Xaml::PropertyMetadata PropertyMetadata::Create(Windows::UI::Xaml::CreateDefaultValueCallback const& createDefaultValueCallback, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
{
    return impl::call_factory<PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataStatics>([&](auto&& f) { return f.Create(createDefaultValueCallback, propertyChangedCallback); });
}

inline PropertyPath::PropertyPath(param::hstring const& path) :
    PropertyPath(impl::call_factory<PropertyPath, Windows::UI::Xaml::IPropertyPathFactory>([&](auto&& f) { return f.CreateInstance(path); }))
{}

inline Windows::Foundation::Rect RectHelper::Empty()
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Empty(); });
}

inline Windows::Foundation::Rect RectHelper::FromCoordinatesAndDimensions(float x, float y, float width, float height)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.FromCoordinatesAndDimensions(x, y, width, height); });
}

inline Windows::Foundation::Rect RectHelper::FromPoints(Windows::Foundation::Point const& point1, Windows::Foundation::Point const& point2)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.FromPoints(point1, point2); });
}

inline Windows::Foundation::Rect RectHelper::FromLocationAndSize(Windows::Foundation::Point const& location, Windows::Foundation::Size const& size)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.FromLocationAndSize(location, size); });
}

inline bool RectHelper::GetIsEmpty(Windows::Foundation::Rect const& target)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.GetIsEmpty(target); });
}

inline float RectHelper::GetBottom(Windows::Foundation::Rect const& target)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.GetBottom(target); });
}

inline float RectHelper::GetLeft(Windows::Foundation::Rect const& target)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.GetLeft(target); });
}

inline float RectHelper::GetRight(Windows::Foundation::Rect const& target)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.GetRight(target); });
}

inline float RectHelper::GetTop(Windows::Foundation::Rect const& target)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.GetTop(target); });
}

inline bool RectHelper::Contains(Windows::Foundation::Rect const& target, Windows::Foundation::Point const& point)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Contains(target, point); });
}

inline bool RectHelper::Equals(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& value)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline Windows::Foundation::Rect RectHelper::Intersect(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& rect)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Intersect(target, rect); });
}

inline Windows::Foundation::Rect RectHelper::Union(Windows::Foundation::Rect const& target, Windows::Foundation::Point const& point)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Union(target, point); });
}

inline Windows::Foundation::Rect RectHelper::Union(Windows::Foundation::Rect const& target, Windows::Foundation::Rect const& rect)
{
    return impl::call_factory<RectHelper, Windows::UI::Xaml::IRectHelperStatics>([&](auto&& f) { return f.Union(target, rect); });
}

inline ResourceDictionary::ResourceDictionary()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ResourceDictionary, Windows::UI::Xaml::IResourceDictionaryFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline RoutedEventArgs::RoutedEventArgs()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline ScalarTransition::ScalarTransition()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ScalarTransition, Windows::UI::Xaml::IScalarTransitionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Setter::Setter() :
    Setter(impl::call_factory<Setter>([](auto&& f) { return f.template ActivateInstance<Setter>(); }))
{}

inline Setter::Setter(Windows::UI::Xaml::DependencyProperty const& targetProperty, Windows::Foundation::IInspectable const& value) :
    Setter(impl::call_factory<Setter, Windows::UI::Xaml::ISetterFactory>([&](auto&& f) { return f.CreateInstance(targetProperty, value); }))
{}

inline SetterBaseCollection::SetterBaseCollection() :
    SetterBaseCollection(impl::call_factory<SetterBaseCollection>([](auto&& f) { return f.template ActivateInstance<SetterBaseCollection>(); }))
{}

inline Windows::Foundation::Size SizeHelper::Empty()
{
    return impl::call_factory<SizeHelper, Windows::UI::Xaml::ISizeHelperStatics>([&](auto&& f) { return f.Empty(); });
}

inline Windows::Foundation::Size SizeHelper::FromDimensions(float width, float height)
{
    return impl::call_factory<SizeHelper, Windows::UI::Xaml::ISizeHelperStatics>([&](auto&& f) { return f.FromDimensions(width, height); });
}

inline bool SizeHelper::GetIsEmpty(Windows::Foundation::Size const& target)
{
    return impl::call_factory<SizeHelper, Windows::UI::Xaml::ISizeHelperStatics>([&](auto&& f) { return f.GetIsEmpty(target); });
}

inline bool SizeHelper::Equals(Windows::Foundation::Size const& target, Windows::Foundation::Size const& value)
{
    return impl::call_factory<SizeHelper, Windows::UI::Xaml::ISizeHelperStatics>([&](auto&& f) { return f.Equals(target, value); });
}

inline StateTrigger::StateTrigger() :
    StateTrigger(impl::call_factory<StateTrigger>([](auto&& f) { return f.template ActivateInstance<StateTrigger>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty StateTrigger::IsActiveProperty()
{
    return impl::call_factory<StateTrigger, Windows::UI::Xaml::IStateTriggerStatics>([&](auto&& f) { return f.IsActiveProperty(); });
}

inline Style::Style() :
    Style(impl::call_factory<Style>([](auto&& f) { return f.template ActivateInstance<Style>(); }))
{}

inline Style::Style(Windows::UI::Xaml::Interop::TypeName const& targetType) :
    Style(impl::call_factory<Style, Windows::UI::Xaml::IStyleFactory>([&](auto&& f) { return f.CreateInstance(targetType); }))
{}

inline TargetPropertyPath::TargetPropertyPath() :
    TargetPropertyPath(impl::call_factory<TargetPropertyPath>([](auto&& f) { return f.template ActivateInstance<TargetPropertyPath>(); }))
{}

inline TargetPropertyPath::TargetPropertyPath(Windows::UI::Xaml::DependencyProperty const& targetProperty) :
    TargetPropertyPath(impl::call_factory<TargetPropertyPath, Windows::UI::Xaml::ITargetPropertyPathFactory>([&](auto&& f) { return f.CreateInstance(targetProperty); }))
{}

inline Windows::UI::Xaml::Thickness ThicknessHelper::FromLengths(double left, double top, double right, double bottom)
{
    return impl::call_factory<ThicknessHelper, Windows::UI::Xaml::IThicknessHelperStatics>([&](auto&& f) { return f.FromLengths(left, top, right, bottom); });
}

inline Windows::UI::Xaml::Thickness ThicknessHelper::FromUniformLength(double uniformLength)
{
    return impl::call_factory<ThicknessHelper, Windows::UI::Xaml::IThicknessHelperStatics>([&](auto&& f) { return f.FromUniformLength(uniformLength); });
}

inline TriggerActionCollection::TriggerActionCollection() :
    TriggerActionCollection(impl::call_factory<TriggerActionCollection>([](auto&& f) { return f.template ActivateInstance<TriggerActionCollection>(); }))
{}

inline Windows::UI::Xaml::RoutedEvent UIElement::KeyDownEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.KeyDownEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::KeyUpEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.KeyUpEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerEnteredEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerEnteredEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerPressedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerPressedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerMovedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerMovedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerReleasedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerReleasedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerExitedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerExitedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerCaptureLostEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerCaptureLostEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerCanceledEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerCanceledEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PointerWheelChangedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerWheelChangedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::TappedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.TappedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::DoubleTappedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.DoubleTappedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::HoldingEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.HoldingEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::RightTappedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.RightTappedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ManipulationStartingEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationStartingEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ManipulationInertiaStartingEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationInertiaStartingEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ManipulationStartedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationStartedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ManipulationDeltaEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationDeltaEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ManipulationCompletedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationCompletedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::DragEnterEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.DragEnterEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::DragLeaveEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.DragLeaveEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::DragOverEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.DragOverEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::DropEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.DropEvent(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::AllowDropProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.AllowDropProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::OpacityProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.OpacityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ClipProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ClipProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::RenderTransformProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.RenderTransformProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ProjectionProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ProjectionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::RenderTransformOriginProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.RenderTransformOriginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsHitTestVisibleProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.IsHitTestVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::VisibilityProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.VisibilityProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::UseLayoutRoundingProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.UseLayoutRoundingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::TransitionsProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.TransitionsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::CacheModeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.CacheModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsTapEnabledProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.IsTapEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsDoubleTapEnabledProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.IsDoubleTapEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsRightTapEnabledProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.IsRightTapEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsHoldingEnabledProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.IsHoldingEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ManipulationModeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.ManipulationModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::PointerCapturesProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics>([&](auto&& f) { return f.PointerCapturesProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ShadowProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics10>([&](auto&& f) { return f.ShadowProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::CompositeModeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics2>([&](auto&& f) { return f.CompositeModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::Transform3DProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics3>([&](auto&& f) { return f.Transform3DProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::CanDragProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics3>([&](auto&& f) { return f.CanDragProperty(); });
}

inline bool UIElement::TryStartDirectManipulation(Windows::UI::Xaml::Input::Pointer const& value)
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics3>([&](auto&& f) { return f.TryStartDirectManipulation(value); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ContextFlyoutProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics4>([&](auto&& f) { return f.ContextFlyoutProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::ExitDisplayModeOnAccessKeyInvokedProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics4>([&](auto&& f) { return f.ExitDisplayModeOnAccessKeyInvokedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::IsAccessKeyScopeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics4>([&](auto&& f) { return f.IsAccessKeyScopeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::AccessKeyScopeOwnerProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics4>([&](auto&& f) { return f.AccessKeyScopeOwnerProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::AccessKeyProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics4>([&](auto&& f) { return f.AccessKeyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::LightsProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.LightsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyTipPlacementModeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.KeyTipPlacementModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyTipHorizontalOffsetProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.KeyTipHorizontalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyTipVerticalOffsetProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.KeyTipVerticalOffsetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::XYFocusKeyboardNavigationProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.XYFocusKeyboardNavigationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::XYFocusUpNavigationStrategyProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.XYFocusUpNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::XYFocusDownNavigationStrategyProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.XYFocusDownNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::XYFocusLeftNavigationStrategyProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.XYFocusLeftNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::XYFocusRightNavigationStrategyProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.XYFocusRightNavigationStrategyProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::HighContrastAdjustmentProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.HighContrastAdjustmentProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::TabFocusNavigationProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics5>([&](auto&& f) { return f.TabFocusNavigationProperty(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::GettingFocusEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics6>([&](auto&& f) { return f.GettingFocusEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::LosingFocusEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics6>([&](auto&& f) { return f.LosingFocusEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::NoFocusCandidateFoundEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics6>([&](auto&& f) { return f.NoFocusCandidateFoundEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PreviewKeyDownEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics7>([&](auto&& f) { return f.PreviewKeyDownEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::CharacterReceivedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics7>([&](auto&& f) { return f.CharacterReceivedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::PreviewKeyUpEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics7>([&](auto&& f) { return f.PreviewKeyUpEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::BringIntoViewRequestedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.BringIntoViewRequestedEvent(); });
}

inline Windows::UI::Xaml::RoutedEvent UIElement::ContextRequestedEvent()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.ContextRequestedEvent(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyTipTargetProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.KeyTipTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyboardAcceleratorPlacementTargetProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.KeyboardAcceleratorPlacementTargetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::KeyboardAcceleratorPlacementModeProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.KeyboardAcceleratorPlacementModeProperty(); });
}

inline void UIElement::RegisterAsScrollPort(Windows::UI::Xaml::UIElement const& element)
{
    impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics8>([&](auto&& f) { return f.RegisterAsScrollPort(element); });
}

inline Windows::UI::Xaml::DependencyProperty UIElement::CanBeScrollAnchorProperty()
{
    return impl::call_factory<UIElement, Windows::UI::Xaml::IUIElementStatics9>([&](auto&& f) { return f.CanBeScrollAnchorProperty(); });
}

inline UIElementWeakCollection::UIElementWeakCollection()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<UIElementWeakCollection, Windows::UI::Xaml::IUIElementWeakCollectionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Vector3Transition::Vector3Transition()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<Vector3Transition, Windows::UI::Xaml::IVector3TransitionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline VisualState::VisualState() :
    VisualState(impl::call_factory<VisualState>([](auto&& f) { return f.template ActivateInstance<VisualState>(); }))
{}

inline VisualStateChangedEventArgs::VisualStateChangedEventArgs() :
    VisualStateChangedEventArgs(impl::call_factory<VisualStateChangedEventArgs>([](auto&& f) { return f.template ActivateInstance<VisualStateChangedEventArgs>(); }))
{}

inline VisualStateGroup::VisualStateGroup() :
    VisualStateGroup(impl::call_factory<VisualStateGroup>([](auto&& f) { return f.template ActivateInstance<VisualStateGroup>(); }))
{}

inline VisualStateManager::VisualStateManager()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::VisualStateGroup> VisualStateManager::GetVisualStateGroups(Windows::UI::Xaml::FrameworkElement const& obj)
{
    return impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerStatics>([&](auto&& f) { return f.GetVisualStateGroups(obj); });
}

inline Windows::UI::Xaml::DependencyProperty VisualStateManager::CustomVisualStateManagerProperty()
{
    return impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerStatics>([&](auto&& f) { return f.CustomVisualStateManagerProperty(); });
}

inline Windows::UI::Xaml::VisualStateManager VisualStateManager::GetCustomVisualStateManager(Windows::UI::Xaml::FrameworkElement const& obj)
{
    return impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerStatics>([&](auto&& f) { return f.GetCustomVisualStateManager(obj); });
}

inline void VisualStateManager::SetCustomVisualStateManager(Windows::UI::Xaml::FrameworkElement const& obj, Windows::UI::Xaml::VisualStateManager const& value)
{
    impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerStatics>([&](auto&& f) { return f.SetCustomVisualStateManager(obj, value); });
}

inline bool VisualStateManager::GoToState(Windows::UI::Xaml::Controls::Control const& control, param::hstring const& stateName, bool useTransitions)
{
    return impl::call_factory<VisualStateManager, Windows::UI::Xaml::IVisualStateManagerStatics>([&](auto&& f) { return f.GoToState(control, stateName, useTransitions); });
}

inline VisualTransition::VisualTransition()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<VisualTransition, Windows::UI::Xaml::IVisualTransitionFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Window Window::Current()
{
    return impl::call_factory<Window, Windows::UI::Xaml::IWindowStatics>([&](auto&& f) { return f.Current(); });
}

template <typename L> ApplicationInitializationCallback::ApplicationInitializationCallback(L handler) :
    ApplicationInitializationCallback(impl::make_delegate<ApplicationInitializationCallback>(std::forward<L>(handler)))
{}

template <typename F> ApplicationInitializationCallback::ApplicationInitializationCallback(F* handler) :
    ApplicationInitializationCallback([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(O* object, M method) :
    ApplicationInitializationCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(com_ptr<O>&& object, M method) :
    ApplicationInitializationCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ApplicationInitializationCallback::ApplicationInitializationCallback(weak_ref<O>&& object, M method) :
    ApplicationInitializationCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ApplicationInitializationCallback::operator()(Windows::UI::Xaml::ApplicationInitializationCallbackParams const& p) const
{
    check_hresult((*(impl::abi_t<ApplicationInitializationCallback>**)this)->Invoke(get_abi(p)));
}

template <typename L> BindingFailedEventHandler::BindingFailedEventHandler(L handler) :
    BindingFailedEventHandler(impl::make_delegate<BindingFailedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> BindingFailedEventHandler::BindingFailedEventHandler(F* handler) :
    BindingFailedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(O* object, M method) :
    BindingFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(com_ptr<O>&& object, M method) :
    BindingFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> BindingFailedEventHandler::BindingFailedEventHandler(weak_ref<O>&& object, M method) :
    BindingFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void BindingFailedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::BindingFailedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<BindingFailedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> CreateDefaultValueCallback::CreateDefaultValueCallback(L handler) :
    CreateDefaultValueCallback(impl::make_delegate<CreateDefaultValueCallback>(std::forward<L>(handler)))
{}

template <typename F> CreateDefaultValueCallback::CreateDefaultValueCallback(F* handler) :
    CreateDefaultValueCallback([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(O* object, M method) :
    CreateDefaultValueCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(com_ptr<O>&& object, M method) :
    CreateDefaultValueCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> CreateDefaultValueCallback::CreateDefaultValueCallback(weak_ref<O>&& object, M method) :
    CreateDefaultValueCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline Windows::Foundation::IInspectable CreateDefaultValueCallback::operator()() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult((*(impl::abi_t<CreateDefaultValueCallback>**)this)->Invoke(put_abi(result)));
    return result;
}

template <typename L> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(L handler) :
    DependencyPropertyChangedCallback(impl::make_delegate<DependencyPropertyChangedCallback>(std::forward<L>(handler)))
{}

template <typename F> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(F* handler) :
    DependencyPropertyChangedCallback([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(O* object, M method) :
    DependencyPropertyChangedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(com_ptr<O>&& object, M method) :
    DependencyPropertyChangedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedCallback::DependencyPropertyChangedCallback(weak_ref<O>&& object, M method) :
    DependencyPropertyChangedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DependencyPropertyChangedCallback::operator()(Windows::UI::Xaml::DependencyObject const& sender, Windows::UI::Xaml::DependencyProperty const& dp) const
{
    check_hresult((*(impl::abi_t<DependencyPropertyChangedCallback>**)this)->Invoke(get_abi(sender), get_abi(dp)));
}

template <typename L> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(L handler) :
    DependencyPropertyChangedEventHandler(impl::make_delegate<DependencyPropertyChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(F* handler) :
    DependencyPropertyChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(O* object, M method) :
    DependencyPropertyChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(com_ptr<O>&& object, M method) :
    DependencyPropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DependencyPropertyChangedEventHandler::DependencyPropertyChangedEventHandler(weak_ref<O>&& object, M method) :
    DependencyPropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DependencyPropertyChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::DependencyPropertyChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DependencyPropertyChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> DragEventHandler::DragEventHandler(L handler) :
    DragEventHandler(impl::make_delegate<DragEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DragEventHandler::DragEventHandler(F* handler) :
    DragEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DragEventHandler::DragEventHandler(O* object, M method) :
    DragEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DragEventHandler::DragEventHandler(com_ptr<O>&& object, M method) :
    DragEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DragEventHandler::DragEventHandler(weak_ref<O>&& object, M method) :
    DragEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DragEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::DragEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DragEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
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

inline void EnteredBackgroundEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::EnteredBackgroundEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<EnteredBackgroundEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(L handler) :
    ExceptionRoutedEventHandler(impl::make_delegate<ExceptionRoutedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(F* handler) :
    ExceptionRoutedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(O* object, M method) :
    ExceptionRoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(com_ptr<O>&& object, M method) :
    ExceptionRoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ExceptionRoutedEventHandler::ExceptionRoutedEventHandler(weak_ref<O>&& object, M method) :
    ExceptionRoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ExceptionRoutedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::ExceptionRoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<ExceptionRoutedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
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

inline void LeavingBackgroundEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::LeavingBackgroundEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<LeavingBackgroundEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> PropertyChangedCallback::PropertyChangedCallback(L handler) :
    PropertyChangedCallback(impl::make_delegate<PropertyChangedCallback>(std::forward<L>(handler)))
{}

template <typename F> PropertyChangedCallback::PropertyChangedCallback(F* handler) :
    PropertyChangedCallback([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(O* object, M method) :
    PropertyChangedCallback([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(com_ptr<O>&& object, M method) :
    PropertyChangedCallback([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PropertyChangedCallback::PropertyChangedCallback(weak_ref<O>&& object, M method) :
    PropertyChangedCallback([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PropertyChangedCallback::operator()(Windows::UI::Xaml::DependencyObject const& d, Windows::UI::Xaml::DependencyPropertyChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<PropertyChangedCallback>**)this)->Invoke(get_abi(d), get_abi(e)));
}

template <typename L> RoutedEventHandler::RoutedEventHandler(L handler) :
    RoutedEventHandler(impl::make_delegate<RoutedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RoutedEventHandler::RoutedEventHandler(F* handler) :
    RoutedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(O* object, M method) :
    RoutedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(com_ptr<O>&& object, M method) :
    RoutedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RoutedEventHandler::RoutedEventHandler(weak_ref<O>&& object, M method) :
    RoutedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RoutedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<RoutedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> SizeChangedEventHandler::SizeChangedEventHandler(L handler) :
    SizeChangedEventHandler(impl::make_delegate<SizeChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> SizeChangedEventHandler::SizeChangedEventHandler(F* handler) :
    SizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(O* object, M method) :
    SizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(com_ptr<O>&& object, M method) :
    SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SizeChangedEventHandler::SizeChangedEventHandler(weak_ref<O>&& object, M method) :
    SizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SizeChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::SizeChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<SizeChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
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

inline void SuspendingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::ApplicationModel::SuspendingEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<SuspendingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(L handler) :
    UnhandledExceptionEventHandler(impl::make_delegate<UnhandledExceptionEventHandler>(std::forward<L>(handler)))
{}

template <typename F> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(F* handler) :
    UnhandledExceptionEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(O* object, M method) :
    UnhandledExceptionEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(com_ptr<O>&& object, M method) :
    UnhandledExceptionEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> UnhandledExceptionEventHandler::UnhandledExceptionEventHandler(weak_ref<O>&& object, M method) :
    UnhandledExceptionEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void UnhandledExceptionEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::UnhandledExceptionEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<UnhandledExceptionEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> VisualStateChangedEventHandler::VisualStateChangedEventHandler(L handler) :
    VisualStateChangedEventHandler(impl::make_delegate<VisualStateChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> VisualStateChangedEventHandler::VisualStateChangedEventHandler(F* handler) :
    VisualStateChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(O* object, M method) :
    VisualStateChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(com_ptr<O>&& object, M method) :
    VisualStateChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> VisualStateChangedEventHandler::VisualStateChangedEventHandler(weak_ref<O>&& object, M method) :
    VisualStateChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void VisualStateChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::VisualStateChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<VisualStateChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> WindowActivatedEventHandler::WindowActivatedEventHandler(L handler) :
    WindowActivatedEventHandler(impl::make_delegate<WindowActivatedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> WindowActivatedEventHandler::WindowActivatedEventHandler(F* handler) :
    WindowActivatedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(O* object, M method) :
    WindowActivatedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(com_ptr<O>&& object, M method) :
    WindowActivatedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WindowActivatedEventHandler::WindowActivatedEventHandler(weak_ref<O>&& object, M method) :
    WindowActivatedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WindowActivatedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Core::WindowActivatedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<WindowActivatedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> WindowClosedEventHandler::WindowClosedEventHandler(L handler) :
    WindowClosedEventHandler(impl::make_delegate<WindowClosedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> WindowClosedEventHandler::WindowClosedEventHandler(F* handler) :
    WindowClosedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(O* object, M method) :
    WindowClosedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(com_ptr<O>&& object, M method) :
    WindowClosedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WindowClosedEventHandler::WindowClosedEventHandler(weak_ref<O>&& object, M method) :
    WindowClosedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WindowClosedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Core::CoreWindowEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<WindowClosedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(L handler) :
    WindowSizeChangedEventHandler(impl::make_delegate<WindowSizeChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(F* handler) :
    WindowSizeChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(O* object, M method) :
    WindowSizeChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(com_ptr<O>&& object, M method) :
    WindowSizeChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WindowSizeChangedEventHandler::WindowSizeChangedEventHandler(weak_ref<O>&& object, M method) :
    WindowSizeChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WindowSizeChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Core::WindowSizeChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<WindowSizeChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(L handler) :
    WindowVisibilityChangedEventHandler(impl::make_delegate<WindowVisibilityChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(F* handler) :
    WindowVisibilityChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(O* object, M method) :
    WindowVisibilityChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(com_ptr<O>&& object, M method) :
    WindowVisibilityChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WindowVisibilityChangedEventHandler::WindowVisibilityChangedEventHandler(weak_ref<O>&& object, M method) :
    WindowVisibilityChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WindowVisibilityChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Core::VisibilityChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<WindowVisibilityChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D> void IApplicationOverridesT<D>::OnActivated(Windows::ApplicationModel::Activation::IActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnLaunched(Windows::ApplicationModel::Activation::LaunchActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnLaunched(args);
}

template <typename D> void IApplicationOverridesT<D>::OnFileActivated(Windows::ApplicationModel::Activation::FileActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnFileActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnSearchActivated(Windows::ApplicationModel::Activation::SearchActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnSearchActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnShareTargetActivated(Windows::ApplicationModel::Activation::ShareTargetActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnShareTargetActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnFileOpenPickerActivated(Windows::ApplicationModel::Activation::FileOpenPickerActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnFileOpenPickerActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnFileSavePickerActivated(Windows::ApplicationModel::Activation::FileSavePickerActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnFileSavePickerActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnCachedFileUpdaterActivated(Windows::ApplicationModel::Activation::CachedFileUpdaterActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnCachedFileUpdaterActivated(args);
}

template <typename D> void IApplicationOverridesT<D>::OnWindowCreated(Windows::UI::Xaml::WindowCreatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides>().OnWindowCreated(args);
}

template <typename D> void IApplicationOverrides2T<D>::OnBackgroundActivated(Windows::ApplicationModel::Activation::BackgroundActivatedEventArgs const& args) const
{
    return shim().template try_as<IApplicationOverrides2>().OnBackgroundActivated(args);
}

template <typename D> Windows::Foundation::Size IFrameworkElementOverridesT<D>::MeasureOverride(Windows::Foundation::Size const& availableSize) const
{
    return shim().template try_as<IFrameworkElementOverrides>().MeasureOverride(availableSize);
}

template <typename D> Windows::Foundation::Size IFrameworkElementOverridesT<D>::ArrangeOverride(Windows::Foundation::Size const& finalSize) const
{
    return shim().template try_as<IFrameworkElementOverrides>().ArrangeOverride(finalSize);
}

template <typename D> void IFrameworkElementOverridesT<D>::OnApplyTemplate() const
{
    return shim().template try_as<IFrameworkElementOverrides>().OnApplyTemplate();
}

template <typename D> bool IFrameworkElementOverrides2T<D>::GoToElementStateCore(param::hstring const& stateName, bool useTransitions) const
{
    return shim().template try_as<IFrameworkElementOverrides2>().GoToElementStateCore(stateName, useTransitions);
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer IUIElementOverridesT<D>::OnCreateAutomationPeer() const
{
    return shim().template try_as<IUIElementOverrides>().OnCreateAutomationPeer();
}

template <typename D> void IUIElementOverridesT<D>::OnDisconnectVisualChildren() const
{
    return shim().template try_as<IUIElementOverrides>().OnDisconnectVisualChildren();
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IIterable<Windows::Foundation::Point>> IUIElementOverridesT<D>::FindSubElementsForTouchTargeting(Windows::Foundation::Point const& point, Windows::Foundation::Rect const& boundingRect) const
{
    return shim().template try_as<IUIElementOverrides>().FindSubElementsForTouchTargeting(point, boundingRect);
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject> IUIElementOverrides7T<D>::GetChildrenInTabFocusOrder() const
{
    return shim().template try_as<IUIElementOverrides7>().GetChildrenInTabFocusOrder();
}

template <typename D> void IUIElementOverrides7T<D>::OnProcessKeyboardAccelerators(Windows::UI::Xaml::Input::ProcessKeyboardAcceleratorEventArgs const& args) const
{
    return shim().template try_as<IUIElementOverrides7>().OnProcessKeyboardAccelerators(args);
}

template <typename D> void IUIElementOverrides8T<D>::OnKeyboardAcceleratorInvoked(Windows::UI::Xaml::Input::KeyboardAcceleratorInvokedEventArgs const& args) const
{
    return shim().template try_as<IUIElementOverrides8>().OnKeyboardAcceleratorInvoked(args);
}

template <typename D> void IUIElementOverrides8T<D>::OnBringIntoViewRequested(Windows::UI::Xaml::BringIntoViewRequestedEventArgs const& e) const
{
    return shim().template try_as<IUIElementOverrides8>().OnBringIntoViewRequested(e);
}

template <typename D> void IUIElementOverrides9T<D>::PopulatePropertyInfoOverride(param::hstring const& propertyName, Windows::UI::Composition::AnimationPropertyInfo const& animationPropertyInfo) const
{
    return shim().template try_as<IUIElementOverrides9>().PopulatePropertyInfoOverride(propertyName, animationPropertyInfo);
}

template <typename D> bool IVisualStateManagerOverridesT<D>::GoToStateCore(Windows::UI::Xaml::Controls::Control const& control, Windows::UI::Xaml::FrameworkElement const& templateRoot, param::hstring const& stateName, Windows::UI::Xaml::VisualStateGroup const& group, Windows::UI::Xaml::VisualState const& state, bool useTransitions) const
{
    return shim().template try_as<IVisualStateManagerOverrides>().GoToStateCore(control, templateRoot, stateName, group, state, useTransitions);
}

template <typename D, typename... Interfaces>
struct AdaptiveTriggerT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IAdaptiveTrigger, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IStateTriggerBase, Windows::UI::Xaml::IStateTriggerBaseProtected>,
    impl::base<D, Windows::UI::Xaml::AdaptiveTrigger, Windows::UI::Xaml::StateTriggerBase, Windows::UI::Xaml::DependencyObject>
{
    using composable = AdaptiveTrigger;

protected:
    AdaptiveTriggerT()
    {
        impl::call_factory<Windows::UI::Xaml::AdaptiveTrigger, Windows::UI::Xaml::IAdaptiveTriggerFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ApplicationT :
    implements<D, Windows::UI::Xaml::IApplicationOverrides, Windows::UI::Xaml::IApplicationOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IApplication, Windows::UI::Xaml::IApplication2, Windows::UI::Xaml::IApplication3>,
    impl::base<D, Windows::UI::Xaml::Application>,
    Windows::UI::Xaml::IApplicationOverridesT<D>, Windows::UI::Xaml::IApplicationOverrides2T<D>
{
    using composable = Application;

protected:
    ApplicationT()
    {
        impl::call_factory<Windows::UI::Xaml::Application, Windows::UI::Xaml::IApplicationFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct BrushTransitionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IBrushTransition>,
    impl::base<D, Windows::UI::Xaml::BrushTransition>
{
    using composable = BrushTransition;

protected:
    BrushTransitionT()
    {
        impl::call_factory<Windows::UI::Xaml::BrushTransition, Windows::UI::Xaml::IBrushTransitionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorPaletteResourcesT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IColorPaletteResources, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>>, Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IResourceDictionary>,
    impl::base<D, Windows::UI::Xaml::ColorPaletteResources, Windows::UI::Xaml::ResourceDictionary, Windows::UI::Xaml::DependencyObject>
{
    using composable = ColorPaletteResources;

protected:
    ColorPaletteResourcesT()
    {
        impl::call_factory<Windows::UI::Xaml::ColorPaletteResources, Windows::UI::Xaml::IColorPaletteResourcesFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DataTemplateT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IDataTemplate, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IElementFactory, Windows::UI::Xaml::IFrameworkTemplate>,
    impl::base<D, Windows::UI::Xaml::DataTemplate, Windows::UI::Xaml::FrameworkTemplate, Windows::UI::Xaml::DependencyObject>
{
    using composable = DataTemplate;

protected:
    DataTemplateT()
    {
        impl::call_factory<Windows::UI::Xaml::DataTemplate, Windows::UI::Xaml::IDataTemplateFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DataTemplateKeyT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IDataTemplateKey>,
    impl::base<D, Windows::UI::Xaml::DataTemplateKey>
{
    using composable = DataTemplateKey;

protected:
    DataTemplateKeyT()
    {
        impl::call_factory<Windows::UI::Xaml::DataTemplateKey, Windows::UI::Xaml::IDataTemplateKeyFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    DataTemplateKeyT(Windows::Foundation::IInspectable const& dataType)
    {
        impl::call_factory<Windows::UI::Xaml::DataTemplateKey, Windows::UI::Xaml::IDataTemplateKeyFactory>([&](auto&& f) { f.CreateInstanceWithType(dataType, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DependencyObjectT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::DependencyObject>
{
    using composable = DependencyObject;

protected:
    DependencyObjectT()
    {
        impl::call_factory<Windows::UI::Xaml::DependencyObject, Windows::UI::Xaml::IDependencyObjectFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DependencyObjectCollectionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::Foundation::Collections::IObservableVector<Windows::UI::Xaml::DependencyObject>, Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::DependencyObject>, Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::DependencyObjectCollection, Windows::UI::Xaml::DependencyObject>
{
    using composable = DependencyObjectCollection;

protected:
    DependencyObjectCollectionT()
    {
        impl::call_factory<Windows::UI::Xaml::DependencyObjectCollection, Windows::UI::Xaml::IDependencyObjectCollectionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DispatcherTimerT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IDispatcherTimer>,
    impl::base<D, Windows::UI::Xaml::DispatcherTimer>
{
    using composable = DispatcherTimer;

protected:
    DispatcherTimerT()
    {
        impl::call_factory<Windows::UI::Xaml::DispatcherTimer, Windows::UI::Xaml::IDispatcherTimerFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ElementFactoryGetArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IElementFactoryGetArgs>,
    impl::base<D, Windows::UI::Xaml::ElementFactoryGetArgs>
{
    using composable = ElementFactoryGetArgs;

protected:
    ElementFactoryGetArgsT()
    {
        impl::call_factory<Windows::UI::Xaml::ElementFactoryGetArgs, Windows::UI::Xaml::IElementFactoryGetArgsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ElementFactoryRecycleArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IElementFactoryRecycleArgs>,
    impl::base<D, Windows::UI::Xaml::ElementFactoryRecycleArgs>
{
    using composable = ElementFactoryRecycleArgs;

protected:
    ElementFactoryRecycleArgsT()
    {
        impl::call_factory<Windows::UI::Xaml::ElementFactoryRecycleArgs, Windows::UI::Xaml::IElementFactoryRecycleArgsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FrameworkElementT :
    implements<D, Windows::UI::Xaml::IFrameworkElementOverrides, Windows::UI::Xaml::IFrameworkElementOverrides2, Windows::UI::Xaml::IUIElementOverrides, Windows::UI::Xaml::IUIElementOverrides7, Windows::UI::Xaml::IUIElementOverrides8, Windows::UI::Xaml::IUIElementOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IFrameworkElement, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::IVisualElement, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IFrameworkElement2, Windows::UI::Xaml::IFrameworkElement3, Windows::UI::Xaml::IFrameworkElement4, Windows::UI::Xaml::IFrameworkElement6, Windows::UI::Xaml::IFrameworkElement7, Windows::UI::Xaml::IFrameworkElementProtected7, Windows::UI::Xaml::IUIElement, Windows::UI::Xaml::IUIElement10, Windows::UI::Xaml::IUIElement2, Windows::UI::Xaml::IUIElement3, Windows::UI::Xaml::IUIElement4, Windows::UI::Xaml::IUIElement5, Windows::UI::Xaml::IUIElement7, Windows::UI::Xaml::IUIElement8, Windows::UI::Xaml::IUIElement9>,
    impl::base<D, Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::UIElement, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::IFrameworkElementOverridesT<D>, Windows::UI::Xaml::IFrameworkElementOverrides2T<D>, Windows::UI::Xaml::IUIElementOverridesT<D>, Windows::UI::Xaml::IUIElementOverrides7T<D>, Windows::UI::Xaml::IUIElementOverrides8T<D>, Windows::UI::Xaml::IUIElementOverrides9T<D>
{
    using composable = FrameworkElement;

protected:
    FrameworkElementT()
    {
        impl::call_factory<Windows::UI::Xaml::FrameworkElement, Windows::UI::Xaml::IFrameworkElementFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FrameworkTemplateT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IFrameworkTemplate, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::FrameworkTemplate, Windows::UI::Xaml::DependencyObject>
{
    using composable = FrameworkTemplate;

protected:
    FrameworkTemplateT()
    {
        impl::call_factory<Windows::UI::Xaml::FrameworkTemplate, Windows::UI::Xaml::IFrameworkTemplateFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PropertyMetadataT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IPropertyMetadata>,
    impl::base<D, Windows::UI::Xaml::PropertyMetadata>
{
    using composable = PropertyMetadata;

protected:
    PropertyMetadataT(Windows::Foundation::IInspectable const& defaultValue)
    {
        impl::call_factory<Windows::UI::Xaml::PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataFactory>([&](auto&& f) { f.CreateInstanceWithDefaultValue(defaultValue, *this, this->m_inner); });
    }
    PropertyMetadataT(Windows::Foundation::IInspectable const& defaultValue, Windows::UI::Xaml::PropertyChangedCallback const& propertyChangedCallback)
    {
        impl::call_factory<Windows::UI::Xaml::PropertyMetadata, Windows::UI::Xaml::IPropertyMetadataFactory>([&](auto&& f) { f.CreateInstanceWithDefaultValueAndCallback(defaultValue, propertyChangedCallback, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ResourceDictionaryT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IResourceDictionary, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>>, Windows::Foundation::Collections::IMap<Windows::Foundation::IInspectable, Windows::Foundation::IInspectable>, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::ResourceDictionary, Windows::UI::Xaml::DependencyObject>
{
    using composable = ResourceDictionary;

protected:
    ResourceDictionaryT()
    {
        impl::call_factory<Windows::UI::Xaml::ResourceDictionary, Windows::UI::Xaml::IResourceDictionaryFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RoutedEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IRoutedEventArgs>,
    impl::base<D, Windows::UI::Xaml::RoutedEventArgs>
{
    using composable = RoutedEventArgs;

protected:
    RoutedEventArgsT()
    {
        impl::call_factory<Windows::UI::Xaml::RoutedEventArgs, Windows::UI::Xaml::IRoutedEventArgsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ScalarTransitionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IScalarTransition>,
    impl::base<D, Windows::UI::Xaml::ScalarTransition>
{
    using composable = ScalarTransition;

protected:
    ScalarTransitionT()
    {
        impl::call_factory<Windows::UI::Xaml::ScalarTransition, Windows::UI::Xaml::IScalarTransitionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct StateTriggerBaseT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IStateTriggerBase, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IStateTriggerBaseProtected>,
    impl::base<D, Windows::UI::Xaml::StateTriggerBase, Windows::UI::Xaml::DependencyObject>
{
    using composable = StateTriggerBase;

protected:
    StateTriggerBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::StateTriggerBase, Windows::UI::Xaml::IStateTriggerBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct UIElementWeakCollectionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IUIElementWeakCollection, Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::UIElement>, Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement>>,
    impl::base<D, Windows::UI::Xaml::UIElementWeakCollection>
{
    using composable = UIElementWeakCollection;

protected:
    UIElementWeakCollectionT()
    {
        impl::call_factory<Windows::UI::Xaml::UIElementWeakCollection, Windows::UI::Xaml::IUIElementWeakCollectionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct Vector3TransitionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IVector3Transition>,
    impl::base<D, Windows::UI::Xaml::Vector3Transition>
{
    using composable = Vector3Transition;

protected:
    Vector3TransitionT()
    {
        impl::call_factory<Windows::UI::Xaml::Vector3Transition, Windows::UI::Xaml::IVector3TransitionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct VisualStateManagerT :
    implements<D, Windows::UI::Xaml::IVisualStateManagerOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IVisualStateManager, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::IVisualStateManagerProtected>,
    impl::base<D, Windows::UI::Xaml::VisualStateManager, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::IVisualStateManagerOverridesT<D>
{
    using composable = VisualStateManager;

protected:
    VisualStateManagerT()
    {
        impl::call_factory<Windows::UI::Xaml::VisualStateManager, Windows::UI::Xaml::IVisualStateManagerFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct VisualTransitionT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::IVisualTransition, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::VisualTransition, Windows::UI::Xaml::DependencyObject>
{
    using composable = VisualTransition;

protected:
    VisualTransitionT()
    {
        impl::call_factory<Windows::UI::Xaml::VisualTransition, Windows::UI::Xaml::IVisualTransitionFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IAdaptiveTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IAdaptiveTriggerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IAdaptiveTriggerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplication> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplication> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplication2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplication2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplication3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplication3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplicationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplicationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplicationInitializationCallbackParams> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplicationInitializationCallbackParams> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplicationOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplicationOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplicationOverrides2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplicationOverrides2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IApplicationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IApplicationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBindingFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBindingFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBringIntoViewOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewOptions2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBringIntoViewOptions2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBringIntoViewRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBrushTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBrushTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::IBrushTransitionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IBrushTransitionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IColorPaletteResources> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IColorPaletteResources> {};
template<> struct hash<winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IColorPaletteResourcesFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ICornerRadiusHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ICornerRadiusHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ICornerRadiusHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataContextChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataContextChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplate> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplate> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateExtension> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplateExtension> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplateFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateKey> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplateKey> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateKeyFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplateKeyFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDataTemplateStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDataTemplateStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDebugSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDebugSettings2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDebugSettings3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDebugSettings4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDebugSettings4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObject> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyObject> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObject2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyObject2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyObjectCollectionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyObjectFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyObjectFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyProperty> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyProperty> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyPropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDependencyPropertyStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDependencyPropertyStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDispatcherTimer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDispatcherTimer> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDispatcherTimerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDispatcherTimerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragEventArgs3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragEventArgs3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragOperationDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragOperationDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragStartingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragStartingEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragStartingEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragUI> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragUI> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDragUIOverride> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDragUIOverride> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDropCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDropCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDurationHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDurationHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::IDurationHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IDurationHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IEffectiveViewportChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryGetArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementFactoryGetArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementFactoryGetArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementFactoryRecycleArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementSoundPlayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IElementSoundPlayerStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IEventTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IEventTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IExceptionRoutedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement6> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElement7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElement7> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementOverrides2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementOverrides2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementProtected7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementProtected7> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkElementStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkElementStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkTemplate> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkTemplate> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkTemplateFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkTemplateFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkView> {};
template<> struct hash<winrt::Windows::UI::Xaml::IFrameworkViewSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IFrameworkViewSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::IGridLengthHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IGridLengthHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::IGridLengthHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IGridLengthHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IMediaFailedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPointHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPointHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPointHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPointHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadata> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPropertyMetadata> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadataFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPropertyMetadataFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPropertyMetadataStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPropertyMetadataStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPropertyPath> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPropertyPath> {};
template<> struct hash<winrt::Windows::UI::Xaml::IPropertyPathFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IPropertyPathFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IRectHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IRectHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::IRectHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IRectHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IResourceDictionary> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IResourceDictionary> {};
template<> struct hash<winrt::Windows::UI::Xaml::IResourceDictionaryFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IResourceDictionaryFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEvent> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IRoutedEvent> {};
template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IRoutedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IRoutedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IScalarTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IScalarTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::IScalarTransitionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IScalarTransitionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetter> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetter2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetter2> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetterBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetterBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetterBaseCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetterBaseCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetterBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetterBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISetterFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISetterFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISizeChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISizeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISizeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::ISizeHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ISizeHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStateTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStateTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStateTriggerBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStateTriggerBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerBaseProtected> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStateTriggerBaseProtected> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStateTriggerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStateTriggerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStyle> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStyle> {};
template<> struct hash<winrt::Windows::UI::Xaml::IStyleFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IStyleFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITargetPropertyPath> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITargetPropertyPath> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITargetPropertyPathFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITargetPropertyPathFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IThicknessHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IThicknessHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::IThicknessHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IThicknessHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITriggerAction> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITriggerAction> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITriggerActionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITriggerActionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITriggerBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITriggerBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::ITriggerBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ITriggerBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement10> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement10> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement5> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement7> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement8> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElement9> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElement9> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementOverrides7> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementOverrides8> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementOverrides9> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementOverrides9> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics10> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics10> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics7> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics8> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementStatics9> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementStatics9> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementWeakCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementWeakCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUIElementWeakCollectionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IUnhandledExceptionEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVector3Transition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVector3Transition> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVector3TransitionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVector3TransitionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualState> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualState> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualState2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualState2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateManagerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateManagerOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerProtected> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateManagerProtected> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualStateManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualStateManagerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::IVisualTransitionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IVisualTransitionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindow> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindow> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindow2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindow2> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindow3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindow3> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindow4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindow4> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindowCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindowCreatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::IWindowStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IWindowStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::IXamlRoot> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IXamlRoot> {};
template<> struct hash<winrt::Windows::UI::Xaml::IXamlRootChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::IXamlRootChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::AdaptiveTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::AdaptiveTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::Application> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Application> {};
template<> struct hash<winrt::Windows::UI::Xaml::ApplicationInitializationCallbackParams> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ApplicationInitializationCallbackParams> {};
template<> struct hash<winrt::Windows::UI::Xaml::BindingFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::BindingFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::BringIntoViewOptions> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::BringIntoViewOptions> {};
template<> struct hash<winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::BringIntoViewRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::BrushTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::BrushTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::ColorPaletteResources> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ColorPaletteResources> {};
template<> struct hash<winrt::Windows::UI::Xaml::CornerRadiusHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::CornerRadiusHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::DataContextChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DataContextChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::DataTemplate> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DataTemplate> {};
template<> struct hash<winrt::Windows::UI::Xaml::DataTemplateKey> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DataTemplateKey> {};
template<> struct hash<winrt::Windows::UI::Xaml::DebugSettings> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DebugSettings> {};
template<> struct hash<winrt::Windows::UI::Xaml::DependencyObject> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DependencyObject> {};
template<> struct hash<winrt::Windows::UI::Xaml::DependencyObjectCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DependencyObjectCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::DependencyProperty> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DependencyProperty> {};
template<> struct hash<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DependencyPropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::DispatcherTimer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DispatcherTimer> {};
template<> struct hash<winrt::Windows::UI::Xaml::DragEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DragEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::DragOperationDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DragOperationDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::DragStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DragStartingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::DragUI> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DragUI> {};
template<> struct hash<winrt::Windows::UI::Xaml::DragUIOverride> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DragUIOverride> {};
template<> struct hash<winrt::Windows::UI::Xaml::DropCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DropCompletedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::DurationHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::DurationHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::EffectiveViewportChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::ElementFactoryGetArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ElementFactoryGetArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ElementFactoryRecycleArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::ElementSoundPlayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ElementSoundPlayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::EventTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::EventTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::ExceptionRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ExceptionRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::FrameworkElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::FrameworkElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::FrameworkTemplate> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::FrameworkTemplate> {};
template<> struct hash<winrt::Windows::UI::Xaml::FrameworkView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::FrameworkView> {};
template<> struct hash<winrt::Windows::UI::Xaml::FrameworkViewSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::FrameworkViewSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::GridLengthHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::GridLengthHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::MediaFailedRoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::MediaFailedRoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::PointHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::PointHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::PropertyMetadata> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::PropertyMetadata> {};
template<> struct hash<winrt::Windows::UI::Xaml::PropertyPath> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::PropertyPath> {};
template<> struct hash<winrt::Windows::UI::Xaml::RectHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::RectHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::ResourceDictionary> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ResourceDictionary> {};
template<> struct hash<winrt::Windows::UI::Xaml::RoutedEvent> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::RoutedEvent> {};
template<> struct hash<winrt::Windows::UI::Xaml::RoutedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::RoutedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::ScalarTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ScalarTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Setter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Setter> {};
template<> struct hash<winrt::Windows::UI::Xaml::SetterBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::SetterBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::SetterBaseCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::SetterBaseCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::SizeChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::SizeChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::SizeHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::SizeHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::StateTrigger> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::StateTrigger> {};
template<> struct hash<winrt::Windows::UI::Xaml::StateTriggerBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::StateTriggerBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Style> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Style> {};
template<> struct hash<winrt::Windows::UI::Xaml::TargetPropertyPath> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::TargetPropertyPath> {};
template<> struct hash<winrt::Windows::UI::Xaml::ThicknessHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::ThicknessHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::TriggerAction> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::TriggerAction> {};
template<> struct hash<winrt::Windows::UI::Xaml::TriggerActionCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::TriggerActionCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::TriggerBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::TriggerBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::TriggerCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::TriggerCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::UIElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::UIElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::UIElementWeakCollection> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::UIElementWeakCollection> {};
template<> struct hash<winrt::Windows::UI::Xaml::UnhandledExceptionEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::UnhandledExceptionEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Vector3Transition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Vector3Transition> {};
template<> struct hash<winrt::Windows::UI::Xaml::VisualState> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::VisualState> {};
template<> struct hash<winrt::Windows::UI::Xaml::VisualStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::VisualStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::VisualStateGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::VisualStateGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::VisualStateManager> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::VisualStateManager> {};
template<> struct hash<winrt::Windows::UI::Xaml::VisualTransition> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::VisualTransition> {};
template<> struct hash<winrt::Windows::UI::Xaml::Window> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Window> {};
template<> struct hash<winrt::Windows::UI::Xaml::WindowCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::WindowCreatedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::XamlRoot> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::XamlRoot> {};
template<> struct hash<winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::XamlRootChangedEventArgs> {};

}
