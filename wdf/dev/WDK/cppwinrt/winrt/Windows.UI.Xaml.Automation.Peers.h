// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Provider.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Primitives.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/Windows.UI.Xaml.Automation.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAppBarAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::AppBar const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAppBarButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::AppBarButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAppBarToggleButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::AppBarToggleButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutoSuggestBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::AutoSuggestBox const& owner) const
{
    Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::EventsSource() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->get_EventsSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::EventsSource(Windows::UI::Xaml::Automation::Peers::AutomationPeer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->put_EventsSource(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetPattern(Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetPattern(get_abi(patternInterface), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::RaiseAutomationEvent(Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->RaiseAutomationEvent(get_abi(eventId)));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::RaisePropertyChangedEvent(Windows::UI::Xaml::Automation::AutomationProperty const& automationProperty, Windows::Foundation::IInspectable const& oldValue, Windows::Foundation::IInspectable const& newValue) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->RaisePropertyChangedEvent(get_abi(automationProperty), get_abi(oldValue), get_abi(newValue)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAcceleratorKey() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAcceleratorKey(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAccessKey() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAccessKey(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationControlType consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAutomationControlType() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationControlType result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAutomationControlType(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetAutomationId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetAutomationId(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetBoundingRectangle() const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetBoundingRectangle(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetChildren() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetChildren(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetClassName() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetClassName(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetClickablePoint() const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetClickablePoint(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetHelpText() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetHelpText(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetItemStatus() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetItemStatus(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetItemType() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetItemType(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLabeledBy() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLabeledBy(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLocalizedControlType() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLocalizedControlType(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetName() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetName(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationOrientation consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetOrientation() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationOrientation result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetOrientation(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::HasKeyboardFocus() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->HasKeyboardFocus(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsContentElement() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsContentElement(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsControlElement() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsControlElement(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsEnabled() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsEnabled(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsKeyboardFocusable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsKeyboardFocusable(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsOffscreen() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsOffscreen(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsPassword() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsPassword(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::IsRequiredForForm() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->IsRequiredForForm(&result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::SetFocus() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->SetFocus());
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetParent() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetParent(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::InvalidatePeer() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->InvalidatePeer());
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetPeerFromPoint(Windows::Foundation::Point const& point) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetPeerFromPoint(get_abi(point), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer<D>::GetLiveSetting() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer)->GetLiveSetting(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::Navigate(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->Navigate(get_abi(direction), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetElementFromPoint(Windows::Foundation::Point const& pointInWindowCoordinates) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetElementFromPoint(get_abi(pointInWindowCoordinates), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetFocusedElement() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetFocusedElement(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::ShowContextMenu() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->ShowContextMenu());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetControlledPeers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetControlledPeers(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetAnnotations() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetAnnotations(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::SetParent(Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->SetParent(get_abi(peer)));
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::RaiseTextEditTextChangedEvent(Windows::UI::Xaml::Automation::AutomationTextEditChangeType const& automationTextEditChangeType, param::vector_view<hstring> const& changedData) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->RaiseTextEditTextChangedEvent(get_abi(automationTextEditChangeType), get_abi(changedData)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetPositionInSet() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetPositionInSet(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetSizeOfSet() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetSizeOfSet(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::GetLevel() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->GetLevel(&result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer3<D>::RaiseStructureChangedEvent(Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType const& structureChangeType, Windows::UI::Xaml::Automation::Peers::AutomationPeer const& child) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer3)->RaiseStructureChangedEvent(get_abi(structureChangeType), get_abi(child)));
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer4<D>::GetLandmarkType() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer4)->GetLandmarkType(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer4<D>::GetLocalizedLandmarkType() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer4)->GetLocalizedLandmarkType(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::IsPeripheral() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->IsPeripheral(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::IsDataValidForForm() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->IsDataValidForForm(&result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer5<D>::GetFullDescription() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer5)->GetFullDescription(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer6<D>::GetCulture() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer6)->GetCulture(&result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer7<D>::RaiseNotificationEvent(Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind const& notificationKind, Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing const& notificationProcessing, param::hstring const& displayString, param::hstring const& activityId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer7)->RaiseNotificationEvent(get_abi(notificationKind), get_abi(notificationProcessing), get_abi(displayString), get_abi(activityId)));
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer8<D>::GetHeadingLevel() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer8)->GetHeadingLevel(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeer9<D>::IsDialog() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeer9)->IsDialog(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::AnnotationType consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Type() const
{
    Windows::UI::Xaml::Automation::AnnotationType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Type(Windows::UI::Xaml::Automation::AnnotationType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->put_Type(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Peer() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->get_Peer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotation<D>::Peer(Windows::UI::Xaml::Automation::Peers::AutomationPeer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation)->put_Peer(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationFactory<D>::CreateInstance(Windows::UI::Xaml::Automation::AnnotationType const& type) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory)->CreateInstance(get_abi(type), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationFactory<D>::CreateWithPeerParameter(Windows::UI::Xaml::Automation::AnnotationType const& type, Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory)->CreateWithPeerParameter(get_abi(type), get_abi(peer), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationStatics<D>::TypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics)->get_TypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerAnnotationStatics<D>::PeerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics)->get_PeerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetPatternCore(Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetPatternCore(get_abi(patternInterface), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAcceleratorKeyCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAcceleratorKeyCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAccessKeyCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAccessKeyCore(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationControlType consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAutomationControlTypeCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationControlType result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAutomationControlTypeCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetAutomationIdCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetAutomationIdCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetBoundingRectangleCore() const
{
    Windows::Foundation::Rect result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetBoundingRectangleCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetChildrenCore() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetChildrenCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetClassNameCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetClassNameCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetClickablePointCore() const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetClickablePointCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetHelpTextCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetHelpTextCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetItemStatusCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetItemStatusCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetItemTypeCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetItemTypeCore(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLabeledByCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLabeledByCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLocalizedControlTypeCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLocalizedControlTypeCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetNameCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetNameCore(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationOrientation consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetOrientationCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationOrientation result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetOrientationCore(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::HasKeyboardFocusCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->HasKeyboardFocusCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsContentElementCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsContentElementCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsControlElementCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsControlElementCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsEnabledCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsEnabledCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsKeyboardFocusableCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsKeyboardFocusableCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsOffscreenCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsOffscreenCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsPasswordCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsPasswordCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::IsRequiredForFormCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->IsRequiredForFormCore(&result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::SetFocusCore() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->SetFocusCore());
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetPeerFromPointCore(Windows::Foundation::Point const& point) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetPeerFromPointCore(get_abi(point), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides<D>::GetLiveSettingCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides)->GetLiveSettingCore(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides2<D>::ShowContextMenuCore() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2)->ShowContextMenuCore());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides2<D>::GetControlledPeersCore() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2)->GetControlledPeersCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::NavigateCore(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->NavigateCore(get_abi(direction), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetElementFromPointCore(Windows::Foundation::Point const& pointInWindowCoordinates) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetElementFromPointCore(get_abi(pointInWindowCoordinates), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetFocusedElementCore() const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetFocusedElementCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetAnnotationsCore() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetAnnotationsCore(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetPositionInSetCore() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetPositionInSetCore(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetSizeOfSetCore() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetSizeOfSetCore(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides3<D>::GetLevelCore() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3)->GetLevelCore(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides4<D>::GetLandmarkTypeCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4)->GetLandmarkTypeCore(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides4<D>::GetLocalizedLandmarkTypeCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4)->GetLocalizedLandmarkTypeCore(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::IsPeripheralCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->IsPeripheralCore(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::IsDataValidForFormCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->IsDataValidForFormCore(&result));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFullDescriptionCore() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFullDescriptionCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetDescribedByCore() const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetDescribedByCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFlowsToCore() const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFlowsToCore(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides5<D>::GetFlowsFromCore() const
{
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5)->GetFlowsFromCore(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides6<D>::GetCultureCore() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6)->GetCultureCore(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides8<D>::GetHeadingLevelCore() const
{
    Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8)->GetHeadingLevelCore(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerOverrides9<D>::IsDialogCore() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9)->IsDialogCore(&result));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerProtected<D>::PeerFromProvider(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const& provider) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected)->PeerFromProvider(get_abi(provider), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerProtected<D>::ProviderFromPeer(Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) const
{
    Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected)->ProviderFromPeer(get_abi(peer), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerStatics<D>::ListenerExists(Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics)->ListenerExists(get_abi(eventId), &result));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId consume_Windows_UI_Xaml_Automation_Peers_IAutomationPeerStatics3<D>::GenerateRawElementProviderRuntimeId() const
{
    Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3)->GenerateRawElementProviderRuntimeId(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Button const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IButtonBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::ButtonBase const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ICalendarDatePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::CalendarDatePicker const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ICaptureElementAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::CaptureElement const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ICheckBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::CheckBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IColorPickerSliderAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IColorSpectrumAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IComboBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ComboBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IComboBoxItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ComboBoxItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IComboBoxItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IDatePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::DatePicker const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFlipViewAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::FlipView const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFlipViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::FlipViewItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFlipViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFlyoutPresenterAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::FlyoutPresenter const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeer<D>::Owner() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer)->get_Owner(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::FrameworkElement const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerStatics<D>::FromElement(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics)->FromElement(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IFrameworkElementAutomationPeerStatics<D>::CreatePeerForElement(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics)->CreatePeerForElement(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IGridViewAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::GridView const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IGridViewHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IGridViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::GridViewItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IGridViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IGroupItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::GroupItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::HubAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IHubAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Hub const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::HubAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IHubSectionAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::HubSection const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IHyperlinkButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::HyperlinkButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IImageAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Image const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeer<D>::Item() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer)->get_Item(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeer<D>::ItemsControlAutomationPeer() const
{
    Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer)->get_ItemsControlAutomationPeer(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IItemAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeer2<D>::CreateItemAutomationPeer(Windows::Foundation::IInspectable const& item) const
{
    Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2)->CreateItemAutomationPeer(get_abi(item), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ItemsControl const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IItemsControlAutomationPeerOverrides2<D>::OnCreateItemAutomationPeer(Windows::Foundation::IInspectable const& item) const
{
    Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2)->OnCreateItemAutomationPeer(get_abi(item), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListBoxItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListBoxItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListBoxItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListView const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListViewBase const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewBaseHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewHeaderItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ListViewItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IListViewItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMediaElementAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::MediaElement const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMediaPlayerElementAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::MediaPlayerElement const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMediaTransportControlsAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::MediaTransportControls const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMenuBarAutomationPeerFactory<D>::CreateInstance(Windows::UI::Xaml::Controls::MenuBar const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory)->CreateInstance(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMenuBarItemAutomationPeerFactory<D>::CreateInstance(Windows::UI::Xaml::Controls::MenuBarItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory)->CreateInstance(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMenuFlyoutItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IMenuFlyoutPresenterAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_INavigationViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::NavigationViewItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IPasswordBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::PasswordBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IPersonPictureAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::PersonPicture const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IPivotAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Pivot const& owner) const
{
    Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IPivotItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::PivotItem const& owner) const
{
    Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IPivotItemDataAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const& parent) const
{
    Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IProgressBarAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ProgressBar const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IProgressRingAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ProgressRing const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRadioButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::RadioButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRangeBaseAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRatingControlAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::RatingControl const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRepeatButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRichEditBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::RichEditBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRichTextBlockAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::RichTextBlock const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IRichTextBlockOverflowAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IScrollBarAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IScrollViewerAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ScrollViewer const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISearchBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::SearchBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISelectorAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::Selector const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISelectorItemAutomationPeerFactory<D>::CreateInstanceWithParentAndItem(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory)->CreateInstanceWithParentAndItem(get_abi(item), get_abi(parent), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISemanticZoomAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::SemanticZoom const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISettingsFlyoutAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::SettingsFlyout const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ISliderAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Slider const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ITextBlockAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::TextBlock const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ITextBoxAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::TextBox const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IThumbAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::Thumb const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ITimePickerAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::TimePicker const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IToggleButtonAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IToggleMenuFlyoutItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_IToggleSwitchAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::ToggleSwitch const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ITreeViewItemAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::TreeViewItem const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer consume_Windows_UI_Xaml_Automation_Peers_ITreeViewListAutomationPeerFactory<D>::CreateInstanceWithOwner(Windows::UI::Xaml::Controls::TreeViewList const& owner, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory)->CreateInstanceWithOwner(get_abi(owner), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer), Windows::UI::Xaml::Controls::AppBar const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::AppBar const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer), Windows::UI::Xaml::Controls::AppBarButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::AppBarButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer), Windows::UI::Xaml::Controls::AppBarToggleButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::AppBarToggleButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer), Windows::UI::Xaml::Controls::AutoSuggestBox const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::AutoSuggestBox const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer>
{
    int32_t WINRT_CALL get_EventsSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventsSource, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().EventsSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EventsSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventsSource, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            this->shim().EventsSource(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPattern(Windows::UI::Xaml::Automation::Peers::PatternInterface patternInterface, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPattern, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Automation::Peers::PatternInterface const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetPattern(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::PatternInterface const*>(&patternInterface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RaiseAutomationEvent(Windows::UI::Xaml::Automation::Peers::AutomationEvents eventId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseAutomationEvent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationEvents const&);
            this->shim().RaiseAutomationEvent(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationEvents const*>(&eventId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RaisePropertyChangedEvent(void* automationProperty, void* oldValue, void* newValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaisePropertyChangedEvent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::AutomationProperty const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().RaisePropertyChangedEvent(*reinterpret_cast<Windows::UI::Xaml::Automation::AutomationProperty const*>(&automationProperty), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&oldValue), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&newValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAcceleratorKey(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAcceleratorKey, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAcceleratorKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccessKey(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccessKey, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAccessKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomationControlType(Windows::UI::Xaml::Automation::Peers::AutomationControlType* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomationControlType, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationControlType));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationControlType>(this->shim().GetAutomationControlType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomationId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomationId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAutomationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBoundingRectangle(Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoundingRectangle, WINRT_WRAP(Windows::Foundation::Rect));
            *result = detach_from<Windows::Foundation::Rect>(this->shim().GetBoundingRectangle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChildren(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChildren, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetChildren());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClassName(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClassName, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetClassName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClickablePoint(Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClickablePoint, WINRT_WRAP(Windows::Foundation::Point));
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetClickablePoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHelpText(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHelpText, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetHelpText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemStatus(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemStatus, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetItemStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemType(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemType, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetItemType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLabeledBy(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLabeledBy, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetLabeledBy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedControlType(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedControlType, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetLocalizedControlType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetName(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetName, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOrientation(Windows::UI::Xaml::Automation::Peers::AutomationOrientation* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOrientation, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationOrientation));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationOrientation>(this->shim().GetOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HasKeyboardFocus(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasKeyboardFocus, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().HasKeyboardFocus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsContentElement(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentElement, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsContentElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsControlElement(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsControlElement, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsControlElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEnabled(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsKeyboardFocusable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsKeyboardFocusable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsKeyboardFocusable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsOffscreen(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOffscreen, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsOffscreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPassword(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPassword, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsPassword());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsRequiredForForm(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequiredForForm, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsRequiredForForm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFocus() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFocus, WINRT_WRAP(void));
            this->shim().SetFocus();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetParent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetParent, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetParent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidatePeer() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidatePeer, WINRT_WRAP(void));
            this->shim().InvalidatePeer();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPeerFromPoint(Windows::Foundation::Point point, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPeerFromPoint, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::Foundation::Point const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetPeerFromPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLiveSetting(Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLiveSetting, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting>(this->shim().GetLiveSetting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3>
{
    int32_t WINRT_CALL Navigate(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection direction, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Navigate, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().Navigate(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetElementFromPoint(Windows::Foundation::Point pointInWindowCoordinates, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetElementFromPoint, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetElementFromPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&pointInWindowCoordinates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFocusedElement(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFocusedElement, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetFocusedElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowContextMenu() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowContextMenu, WINRT_WRAP(void));
            this->shim().ShowContextMenu();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetControlledPeers(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControlledPeers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetControlledPeers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotations(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotations, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>>(this->shim().GetAnnotations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetParent(void* peer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetParent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            this->shim().SetParent(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RaiseTextEditTextChangedEvent(Windows::UI::Xaml::Automation::AutomationTextEditChangeType automationTextEditChangeType, void* changedData) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseTextEditTextChangedEvent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::AutomationTextEditChangeType const&, Windows::Foundation::Collections::IVectorView<hstring> const&);
            this->shim().RaiseTextEditTextChangedEvent(*reinterpret_cast<Windows::UI::Xaml::Automation::AutomationTextEditChangeType const*>(&automationTextEditChangeType), *reinterpret_cast<Windows::Foundation::Collections::IVectorView<hstring> const*>(&changedData));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPositionInSet(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPositionInSet, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetPositionInSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSizeOfSet(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSizeOfSet, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetSizeOfSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLevel(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLevel, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RaiseStructureChangedEvent(Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType structureChangeType, void* child) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseStructureChangedEvent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType const&, Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            this->shim().RaiseStructureChangedEvent(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationStructureChangeType const*>(&structureChangeType), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&child));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4>
{
    int32_t WINRT_CALL GetLandmarkType(Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLandmarkType, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType>(this->shim().GetLandmarkType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedLandmarkType(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedLandmarkType, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetLocalizedLandmarkType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5>
{
    int32_t WINRT_CALL IsPeripheral(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPeripheral, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsPeripheral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsDataValidForForm(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataValidForForm, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsDataValidForForm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFullDescription(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFullDescription, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetFullDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6>
{
    int32_t WINRT_CALL GetCulture(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCulture, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetCulture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7>
{
    int32_t WINRT_CALL RaiseNotificationEvent(Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind notificationKind, Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing notificationProcessing, void* displayString, void* activityId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RaiseNotificationEvent, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind const&, Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing const&, hstring const&, hstring const&);
            this->shim().RaiseNotificationEvent(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationNotificationKind const*>(&notificationKind), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationNotificationProcessing const*>(&notificationProcessing), *reinterpret_cast<hstring const*>(&displayString), *reinterpret_cast<hstring const*>(&activityId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8>
{
    int32_t WINRT_CALL GetHeadingLevel(Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHeadingLevel, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel>(this->shim().GetHeadingLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9>
{
    int32_t WINRT_CALL IsDialog(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDialog, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsDialog());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation>
{
    int32_t WINRT_CALL get_Type(Windows::UI::Xaml::Automation::AnnotationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Xaml::Automation::AnnotationType));
            *value = detach_from<Windows::UI::Xaml::Automation::AnnotationType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(Windows::UI::Xaml::Automation::AnnotationType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), Windows::UI::Xaml::Automation::AnnotationType const&);
            this->shim().Type(*reinterpret_cast<Windows::UI::Xaml::Automation::AnnotationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Peer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Peer, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().Peer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Peer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Peer, WINRT_WRAP(void), Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            this->shim().Peer(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Automation::AnnotationType type, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation), Windows::UI::Xaml::Automation::AnnotationType const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Automation::AnnotationType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPeerParameter(Windows::UI::Xaml::Automation::AnnotationType type, void* peer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPeerParameter, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation), Windows::UI::Xaml::Automation::AnnotationType const&, Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>(this->shim().CreateWithPeerParameter(*reinterpret_cast<Windows::UI::Xaml::Automation::AnnotationType const*>(&type), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics>
{
    int32_t WINRT_CALL get_TypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PeerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
{
    int32_t WINRT_CALL GetPatternCore(Windows::UI::Xaml::Automation::Peers::PatternInterface patternInterface, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPatternCore, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Automation::Peers::PatternInterface const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetPatternCore(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::PatternInterface const*>(&patternInterface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAcceleratorKeyCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAcceleratorKeyCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAcceleratorKeyCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccessKeyCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccessKeyCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAccessKeyCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomationControlTypeCore(Windows::UI::Xaml::Automation::Peers::AutomationControlType* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomationControlTypeCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationControlType));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationControlType>(this->shim().GetAutomationControlTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomationIdCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomationIdCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetAutomationIdCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBoundingRectangleCore(Windows::Foundation::Rect* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoundingRectangleCore, WINRT_WRAP(Windows::Foundation::Rect));
            *result = detach_from<Windows::Foundation::Rect>(this->shim().GetBoundingRectangleCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChildrenCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChildrenCore, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetChildrenCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClassNameCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClassNameCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetClassNameCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClickablePointCore(Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClickablePointCore, WINRT_WRAP(Windows::Foundation::Point));
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetClickablePointCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHelpTextCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHelpTextCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetHelpTextCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemStatusCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemStatusCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetItemStatusCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemTypeCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemTypeCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetItemTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLabeledByCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLabeledByCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetLabeledByCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedControlTypeCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedControlTypeCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetLocalizedControlTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNameCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNameCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetNameCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOrientationCore(Windows::UI::Xaml::Automation::Peers::AutomationOrientation* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOrientationCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationOrientation));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationOrientation>(this->shim().GetOrientationCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HasKeyboardFocusCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasKeyboardFocusCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().HasKeyboardFocusCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsContentElementCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentElementCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsContentElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsControlElementCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsControlElementCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsControlElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEnabledCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsEnabledCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsKeyboardFocusableCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsKeyboardFocusableCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsKeyboardFocusableCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsOffscreenCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOffscreenCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsOffscreenCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsPasswordCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPasswordCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsPasswordCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsRequiredForFormCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequiredForFormCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsRequiredForFormCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFocusCore() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFocusCore, WINRT_WRAP(void));
            this->shim().SetFocusCore();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPeerFromPointCore(Windows::Foundation::Point point, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPeerFromPointCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::Foundation::Point const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().GetPeerFromPointCore(*reinterpret_cast<Windows::Foundation::Point const*>(&point)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLiveSettingCore(Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLiveSettingCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting>(this->shim().GetLiveSettingCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
{
    int32_t WINRT_CALL ShowContextMenuCore() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowContextMenuCore, WINRT_WRAP(void));
            this->shim().ShowContextMenuCore();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetControlledPeersCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControlledPeersCore, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetControlledPeersCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
{
    int32_t WINRT_CALL NavigateCore(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection direction, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavigateCore, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().NavigateCore(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetElementFromPointCore(Windows::Foundation::Point pointInWindowCoordinates, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetElementFromPointCore, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetElementFromPointCore(*reinterpret_cast<Windows::Foundation::Point const*>(&pointInWindowCoordinates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFocusedElementCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFocusedElementCore, WINRT_WRAP(Windows::Foundation::IInspectable));
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetFocusedElementCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotationsCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotationsCore, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation>>(this->shim().GetAnnotationsCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPositionInSetCore(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPositionInSetCore, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetPositionInSetCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSizeOfSetCore(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSizeOfSetCore, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetSizeOfSetCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLevelCore(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLevelCore, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetLevelCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
{
    int32_t WINRT_CALL GetLandmarkTypeCore(Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLandmarkTypeCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType>(this->shim().GetLandmarkTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedLandmarkTypeCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedLandmarkTypeCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetLocalizedLandmarkTypeCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
{
    int32_t WINRT_CALL IsPeripheralCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPeripheralCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsPeripheralCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsDataValidForFormCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataValidForFormCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsDataValidForFormCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFullDescriptionCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFullDescriptionCore, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetFullDescriptionCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDescribedByCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescribedByCore, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetDescribedByCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlowsToCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlowsToCore, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetFlowsToCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlowsFromCore(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlowsFromCore, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>));
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer>>(this->shim().GetFlowsFromCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
{
    int32_t WINRT_CALL GetCultureCore(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCultureCore, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetCultureCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
{
    int32_t WINRT_CALL GetHeadingLevelCore(Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHeadingLevelCore, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel>(this->shim().GetHeadingLevelCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
{
    int32_t WINRT_CALL IsDialogCore(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDialogCore, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsDialogCore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected>
{
    int32_t WINRT_CALL PeerFromProvider(void* provider, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeerFromProvider, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().PeerFromProvider(*reinterpret_cast<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProviderFromPeer(void* peer, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderFromPeer, WINRT_WRAP(Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple), Windows::UI::Xaml::Automation::Peers::AutomationPeer const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Provider::IRawElementProviderSimple>(this->shim().ProviderFromPeer(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationPeer const*>(&peer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics>
{
    int32_t WINRT_CALL ListenerExists(Windows::UI::Xaml::Automation::Peers::AutomationEvents eventId, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListenerExists, WINRT_WRAP(bool), Windows::UI::Xaml::Automation::Peers::AutomationEvents const&);
            *result = detach_from<bool>(this->shim().ListenerExists(*reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationEvents const*>(&eventId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3>
{
    int32_t WINRT_CALL GenerateRawElementProviderRuntimeId(struct struct_Windows_UI_Xaml_Automation_Peers_RawElementProviderRuntimeId* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenerateRawElementProviderRuntimeId, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId));
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId>(this->shim().GenerateRawElementProviderRuntimeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer), Windows::UI::Xaml::Controls::Button const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Button const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer), Windows::UI::Xaml::Controls::Primitives::ButtonBase const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ButtonBase const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer), Windows::UI::Xaml::Controls::CalendarDatePicker const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::CalendarDatePicker const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer), Windows::UI::Xaml::Controls::CaptureElement const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::CaptureElement const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer), Windows::UI::Xaml::Controls::CheckBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::CheckBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer), Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer), Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer), Windows::UI::Xaml::Controls::ComboBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ComboBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer), Windows::UI::Xaml::Controls::ComboBoxItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ComboBoxItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer), Windows::UI::Xaml::Controls::DatePicker const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::DatePicker const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer), Windows::UI::Xaml::Controls::FlipView const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::FlipView const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer), Windows::UI::Xaml::Controls::FlipViewItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::FlipViewItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer), Windows::UI::Xaml::Controls::FlyoutPresenter const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::FlyoutPresenter const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer>
{
    int32_t WINRT_CALL get_Owner(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Owner, WINRT_WRAP(Windows::UI::Xaml::UIElement));
            *value = detach_from<Windows::UI::Xaml::UIElement>(this->shim().Owner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer), Windows::UI::Xaml::FrameworkElement const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::FrameworkElement const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics>
{
    int32_t WINRT_CALL FromElement(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromElement, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().FromElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePeerForElement(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePeerForElement, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationPeer), Windows::UI::Xaml::UIElement const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationPeer>(this->shim().CreatePeerForElement(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer), Windows::UI::Xaml::Controls::GridView const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::GridView const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer), Windows::UI::Xaml::Controls::GridViewHeaderItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::GridViewHeaderItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer), Windows::UI::Xaml::Controls::GridViewItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::GridViewItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer), Windows::UI::Xaml::Controls::GroupItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::GroupItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::HubAutomationPeer), Windows::UI::Xaml::Controls::Hub const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::HubAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Hub const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer), Windows::UI::Xaml::Controls::HubSection const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::HubSection const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer), Windows::UI::Xaml::Controls::HyperlinkButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::HyperlinkButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer), Windows::UI::Xaml::Controls::Image const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Image const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer>
{
    int32_t WINRT_CALL get_Item(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Item, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemsControlAutomationPeer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsControlAutomationPeer, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer));
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer>(this->shim().ItemsControlAutomationPeer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2>
{
    int32_t WINRT_CALL CreateItemAutomationPeer(void* item, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateItemAutomationPeer, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().CreateItemAutomationPeer(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer), Windows::UI::Xaml::Controls::ItemsControl const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ItemsControl const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
{
    int32_t WINRT_CALL OnCreateItemAutomationPeer(void* item, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnCreateItemAutomationPeer, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer>(this->shim().OnCreateItemAutomationPeer(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer), Windows::UI::Xaml::Controls::ListBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer), Windows::UI::Xaml::Controls::ListBoxItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListBoxItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer), Windows::UI::Xaml::Controls::ListView const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListView const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer), Windows::UI::Xaml::Controls::ListViewBase const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewBase const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer), Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer), Windows::UI::Xaml::Controls::ListViewHeaderItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewHeaderItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer), Windows::UI::Xaml::Controls::ListViewItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ListViewItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer), Windows::UI::Xaml::Controls::MediaElement const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::MediaElement const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer), Windows::UI::Xaml::Controls::MediaPlayerElement const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::MediaPlayerElement const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer), Windows::UI::Xaml::Controls::MediaTransportControls const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::MediaTransportControls const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer), Windows::UI::Xaml::Controls::MenuBar const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Controls::MenuBar const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer), Windows::UI::Xaml::Controls::MenuBarItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Controls::MenuBarItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer), Windows::UI::Xaml::Controls::MenuFlyoutItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::MenuFlyoutItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer), Windows::UI::Xaml::Controls::MenuFlyoutPresenter const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::MenuFlyoutPresenter const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer), Windows::UI::Xaml::Controls::NavigationViewItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::NavigationViewItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer), Windows::UI::Xaml::Controls::PasswordBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::PasswordBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer), Windows::UI::Xaml::Controls::PersonPicture const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::PersonPicture const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer), Windows::UI::Xaml::Controls::Pivot const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Pivot const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer), Windows::UI::Xaml::Controls::PivotItem const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::PivotItem const*>(&owner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const*>(&parent)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer), Windows::UI::Xaml::Controls::ProgressBar const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ProgressBar const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer), Windows::UI::Xaml::Controls::ProgressRing const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ProgressRing const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer), Windows::UI::Xaml::Controls::RadioButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::RadioButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer), Windows::UI::Xaml::Controls::Primitives::RangeBase const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::RangeBase const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer), Windows::UI::Xaml::Controls::RatingControl const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::RatingControl const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer), Windows::UI::Xaml::Controls::Primitives::RepeatButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::RepeatButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer), Windows::UI::Xaml::Controls::RichEditBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::RichEditBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer), Windows::UI::Xaml::Controls::RichTextBlock const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::RichTextBlock const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer), Windows::UI::Xaml::Controls::RichTextBlockOverflow const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::RichTextBlockOverflow const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer), Windows::UI::Xaml::Controls::Primitives::ScrollBar const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ScrollBar const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer), Windows::UI::Xaml::Controls::ScrollViewer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ScrollViewer const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer), Windows::UI::Xaml::Controls::SearchBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::SearchBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer), Windows::UI::Xaml::Controls::Primitives::Selector const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::Selector const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithParentAndItem(void* item, void* parent, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithParentAndItem, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer>(this->shim().CreateInstanceWithParentAndItem(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const*>(&parent), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer), Windows::UI::Xaml::Controls::SemanticZoom const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::SemanticZoom const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer), Windows::UI::Xaml::Controls::SettingsFlyout const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::SettingsFlyout const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer), Windows::UI::Xaml::Controls::Slider const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Slider const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer), Windows::UI::Xaml::Controls::TextBlock const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::TextBlock const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer), Windows::UI::Xaml::Controls::TextBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::TextBox const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer), Windows::UI::Xaml::Controls::Primitives::Thumb const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::Thumb const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer), Windows::UI::Xaml::Controls::TimePicker const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::TimePicker const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer), Windows::UI::Xaml::Controls::Primitives::ToggleButton const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::Primitives::ToggleButton const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer), Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer), Windows::UI::Xaml::Controls::ToggleSwitch const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::ToggleSwitch const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer), Windows::UI::Xaml::Controls::TreeViewItem const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::TreeViewItem const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory> : produce_base<D, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory>
{
    int32_t WINRT_CALL CreateInstanceWithOwner(void* owner, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithOwner, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer), Windows::UI::Xaml::Controls::TreeViewList const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer>(this->shim().CreateInstanceWithOwner(*reinterpret_cast<Windows::UI::Xaml::Controls::TreeViewList const*>(&owner), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides>
{
    Windows::Foundation::IInspectable GetPatternCore(Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface)
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetPatternCore(patternInterface);
        }
        return this->shim().GetPatternCore(patternInterface);
    }
    hstring GetAcceleratorKeyCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetAcceleratorKeyCore();
        }
        return this->shim().GetAcceleratorKeyCore();
    }
    hstring GetAccessKeyCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetAccessKeyCore();
        }
        return this->shim().GetAccessKeyCore();
    }
    Windows::UI::Xaml::Automation::Peers::AutomationControlType GetAutomationControlTypeCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetAutomationControlTypeCore();
        }
        return this->shim().GetAutomationControlTypeCore();
    }
    hstring GetAutomationIdCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetAutomationIdCore();
        }
        return this->shim().GetAutomationIdCore();
    }
    Windows::Foundation::Rect GetBoundingRectangleCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetBoundingRectangleCore();
        }
        return this->shim().GetBoundingRectangleCore();
    }
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> GetChildrenCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetChildrenCore();
        }
        return this->shim().GetChildrenCore();
    }
    hstring GetClassNameCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetClassNameCore();
        }
        return this->shim().GetClassNameCore();
    }
    Windows::Foundation::Point GetClickablePointCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetClickablePointCore();
        }
        return this->shim().GetClickablePointCore();
    }
    hstring GetHelpTextCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetHelpTextCore();
        }
        return this->shim().GetHelpTextCore();
    }
    hstring GetItemStatusCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetItemStatusCore();
        }
        return this->shim().GetItemStatusCore();
    }
    hstring GetItemTypeCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetItemTypeCore();
        }
        return this->shim().GetItemTypeCore();
    }
    Windows::UI::Xaml::Automation::Peers::AutomationPeer GetLabeledByCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLabeledByCore();
        }
        return this->shim().GetLabeledByCore();
    }
    hstring GetLocalizedControlTypeCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLocalizedControlTypeCore();
        }
        return this->shim().GetLocalizedControlTypeCore();
    }
    hstring GetNameCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetNameCore();
        }
        return this->shim().GetNameCore();
    }
    Windows::UI::Xaml::Automation::Peers::AutomationOrientation GetOrientationCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetOrientationCore();
        }
        return this->shim().GetOrientationCore();
    }
    bool HasKeyboardFocusCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.HasKeyboardFocusCore();
        }
        return this->shim().HasKeyboardFocusCore();
    }
    bool IsContentElementCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsContentElementCore();
        }
        return this->shim().IsContentElementCore();
    }
    bool IsControlElementCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsControlElementCore();
        }
        return this->shim().IsControlElementCore();
    }
    bool IsEnabledCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsEnabledCore();
        }
        return this->shim().IsEnabledCore();
    }
    bool IsKeyboardFocusableCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsKeyboardFocusableCore();
        }
        return this->shim().IsKeyboardFocusableCore();
    }
    bool IsOffscreenCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsOffscreenCore();
        }
        return this->shim().IsOffscreenCore();
    }
    bool IsPasswordCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsPasswordCore();
        }
        return this->shim().IsPasswordCore();
    }
    bool IsRequiredForFormCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsRequiredForFormCore();
        }
        return this->shim().IsRequiredForFormCore();
    }
    void SetFocusCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.SetFocusCore();
        }
        return this->shim().SetFocusCore();
    }
    Windows::UI::Xaml::Automation::Peers::AutomationPeer GetPeerFromPointCore(Windows::Foundation::Point const& point)
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetPeerFromPointCore(point);
        }
        return this->shim().GetPeerFromPointCore(point);
    }
    Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting GetLiveSettingCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLiveSettingCore();
        }
        return this->shim().GetLiveSettingCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2>
{
    void ShowContextMenuCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.ShowContextMenuCore();
        }
        return this->shim().ShowContextMenuCore();
    }
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> GetControlledPeersCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetControlledPeersCore();
        }
        return this->shim().GetControlledPeersCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3>
{
    Windows::Foundation::IInspectable NavigateCore(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction)
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.NavigateCore(direction);
        }
        return this->shim().NavigateCore(direction);
    }
    Windows::Foundation::IInspectable GetElementFromPointCore(Windows::Foundation::Point const& pointInWindowCoordinates)
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetElementFromPointCore(pointInWindowCoordinates);
        }
        return this->shim().GetElementFromPointCore(pointInWindowCoordinates);
    }
    Windows::Foundation::IInspectable GetFocusedElementCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetFocusedElementCore();
        }
        return this->shim().GetFocusedElementCore();
    }
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> GetAnnotationsCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetAnnotationsCore();
        }
        return this->shim().GetAnnotationsCore();
    }
    int32_t GetPositionInSetCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetPositionInSetCore();
        }
        return this->shim().GetPositionInSetCore();
    }
    int32_t GetSizeOfSetCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetSizeOfSetCore();
        }
        return this->shim().GetSizeOfSetCore();
    }
    int32_t GetLevelCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLevelCore();
        }
        return this->shim().GetLevelCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4>
{
    Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType GetLandmarkTypeCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLandmarkTypeCore();
        }
        return this->shim().GetLandmarkTypeCore();
    }
    hstring GetLocalizedLandmarkTypeCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetLocalizedLandmarkTypeCore();
        }
        return this->shim().GetLocalizedLandmarkTypeCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5>
{
    bool IsPeripheralCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsPeripheralCore();
        }
        return this->shim().IsPeripheralCore();
    }
    bool IsDataValidForFormCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsDataValidForFormCore();
        }
        return this->shim().IsDataValidForFormCore();
    }
    hstring GetFullDescriptionCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetFullDescriptionCore();
        }
        return this->shim().GetFullDescriptionCore();
    }
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> GetDescribedByCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetDescribedByCore();
        }
        return this->shim().GetDescribedByCore();
    }
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> GetFlowsToCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetFlowsToCore();
        }
        return this->shim().GetFlowsToCore();
    }
    Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> GetFlowsFromCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetFlowsFromCore();
        }
        return this->shim().GetFlowsFromCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6>
{
    int32_t GetCultureCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetCultureCore();
        }
        return this->shim().GetCultureCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8>
{
    Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel GetHeadingLevelCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.GetHeadingLevelCore();
        }
        return this->shim().GetHeadingLevelCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9>
{
    bool IsDialogCore()
    {
        Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.IsDialogCore();
        }
        return this->shim().IsDialogCore();
    }
};
template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2>
{
    Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer OnCreateItemAutomationPeer(Windows::Foundation::IInspectable const& item)
    {
        Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2 overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnCreateItemAutomationPeer(item);
        }
        return this->shim().OnCreateItemAutomationPeer(item);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation::Peers {

inline AppBarAutomationPeer::AppBarAutomationPeer(Windows::UI::Xaml::Controls::AppBar const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<AppBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline AppBarButtonAutomationPeer::AppBarButtonAutomationPeer(Windows::UI::Xaml::Controls::AppBarButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<AppBarButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline AppBarToggleButtonAutomationPeer::AppBarToggleButtonAutomationPeer(Windows::UI::Xaml::Controls::AppBarToggleButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<AppBarToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline AutoSuggestBoxAutomationPeer::AutoSuggestBoxAutomationPeer(Windows::UI::Xaml::Controls::AutoSuggestBox const& owner) :
    AutoSuggestBoxAutomationPeer(impl::call_factory<AutoSuggestBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner); }))
{}

inline bool AutomationPeer::ListenerExists(Windows::UI::Xaml::Automation::Peers::AutomationEvents const& eventId)
{
    return impl::call_factory<AutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics>([&](auto&& f) { return f.ListenerExists(eventId); });
}

inline Windows::UI::Xaml::Automation::Peers::RawElementProviderRuntimeId AutomationPeer::GenerateRawElementProviderRuntimeId()
{
    return impl::call_factory<AutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3>([&](auto&& f) { return f.GenerateRawElementProviderRuntimeId(); });
}

inline AutomationPeerAnnotation::AutomationPeerAnnotation() :
    AutomationPeerAnnotation(impl::call_factory<AutomationPeerAnnotation>([](auto&& f) { return f.template ActivateInstance<AutomationPeerAnnotation>(); }))
{}

inline AutomationPeerAnnotation::AutomationPeerAnnotation(Windows::UI::Xaml::Automation::AnnotationType const& type) :
    AutomationPeerAnnotation(impl::call_factory<AutomationPeerAnnotation, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory>([&](auto&& f) { return f.CreateInstance(type); }))
{}

inline AutomationPeerAnnotation::AutomationPeerAnnotation(Windows::UI::Xaml::Automation::AnnotationType const& type, Windows::UI::Xaml::Automation::Peers::AutomationPeer const& peer) :
    AutomationPeerAnnotation(impl::call_factory<AutomationPeerAnnotation, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory>([&](auto&& f) { return f.CreateWithPeerParameter(type, peer); }))
{}

inline Windows::UI::Xaml::DependencyProperty AutomationPeerAnnotation::TypeProperty()
{
    return impl::call_factory<AutomationPeerAnnotation, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics>([&](auto&& f) { return f.TypeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationPeerAnnotation::PeerProperty()
{
    return impl::call_factory<AutomationPeerAnnotation, Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics>([&](auto&& f) { return f.PeerProperty(); });
}

inline ButtonAutomationPeer::ButtonAutomationPeer(Windows::UI::Xaml::Controls::Button const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline CalendarDatePickerAutomationPeer::CalendarDatePickerAutomationPeer(Windows::UI::Xaml::Controls::CalendarDatePicker const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CalendarDatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline CaptureElementAutomationPeer::CaptureElementAutomationPeer(Windows::UI::Xaml::Controls::CaptureElement const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CaptureElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline CheckBoxAutomationPeer::CheckBoxAutomationPeer(Windows::UI::Xaml::Controls::CheckBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CheckBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ColorPickerSliderAutomationPeer::ColorPickerSliderAutomationPeer(Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ColorPickerSliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ColorSpectrumAutomationPeer::ColorSpectrumAutomationPeer(Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ColorSpectrumAutomationPeer, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ComboBoxAutomationPeer::ComboBoxAutomationPeer(Windows::UI::Xaml::Controls::ComboBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ComboBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ComboBoxItemAutomationPeer::ComboBoxItemAutomationPeer(Windows::UI::Xaml::Controls::ComboBoxItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ComboBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ComboBoxItemDataAutomationPeer::ComboBoxItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ComboBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline DatePickerAutomationPeer::DatePickerAutomationPeer(Windows::UI::Xaml::Controls::DatePicker const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<DatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline FlipViewAutomationPeer::FlipViewAutomationPeer(Windows::UI::Xaml::Controls::FlipView const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FlipViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline FlipViewItemAutomationPeer::FlipViewItemAutomationPeer(Windows::UI::Xaml::Controls::FlipViewItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FlipViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline FlipViewItemDataAutomationPeer::FlipViewItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FlipViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline FlyoutPresenterAutomationPeer::FlyoutPresenterAutomationPeer(Windows::UI::Xaml::Controls::FlyoutPresenter const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline FrameworkElementAutomationPeer::FrameworkElementAutomationPeer(Windows::UI::Xaml::FrameworkElement const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Automation::Peers::AutomationPeer FrameworkElementAutomationPeer::FromElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics>([&](auto&& f) { return f.FromElement(element); });
}

inline Windows::UI::Xaml::Automation::Peers::AutomationPeer FrameworkElementAutomationPeer::CreatePeerForElement(Windows::UI::Xaml::UIElement const& element)
{
    return impl::call_factory<FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics>([&](auto&& f) { return f.CreatePeerForElement(element); });
}

inline GridViewAutomationPeer::GridViewAutomationPeer(Windows::UI::Xaml::Controls::GridView const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GridViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline GridViewHeaderItemAutomationPeer::GridViewHeaderItemAutomationPeer(Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GridViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline GridViewItemAutomationPeer::GridViewItemAutomationPeer(Windows::UI::Xaml::Controls::GridViewItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GridViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline GridViewItemDataAutomationPeer::GridViewItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GridViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline GroupItemAutomationPeer::GroupItemAutomationPeer(Windows::UI::Xaml::Controls::GroupItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<GroupItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline HubAutomationPeer::HubAutomationPeer(Windows::UI::Xaml::Controls::Hub const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<HubAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline HubSectionAutomationPeer::HubSectionAutomationPeer(Windows::UI::Xaml::Controls::HubSection const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<HubSectionAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline HyperlinkButtonAutomationPeer::HyperlinkButtonAutomationPeer(Windows::UI::Xaml::Controls::HyperlinkButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<HyperlinkButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ImageAutomationPeer::ImageAutomationPeer(Windows::UI::Xaml::Controls::Image const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ImageAutomationPeer, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ItemAutomationPeer::ItemAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline ItemsControlAutomationPeer::ItemsControlAutomationPeer(Windows::UI::Xaml::Controls::ItemsControl const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListBoxAutomationPeer::ListBoxAutomationPeer(Windows::UI::Xaml::Controls::ListBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListBoxItemAutomationPeer::ListBoxItemAutomationPeer(Windows::UI::Xaml::Controls::ListBoxItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListBoxItemDataAutomationPeer::ListBoxItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline ListViewAutomationPeer::ListViewAutomationPeer(Windows::UI::Xaml::Controls::ListView const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListViewBaseAutomationPeer::ListViewBaseAutomationPeer(Windows::UI::Xaml::Controls::ListViewBase const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListViewHeaderItemAutomationPeer::ListViewHeaderItemAutomationPeer(Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListViewItemAutomationPeer::ListViewItemAutomationPeer(Windows::UI::Xaml::Controls::ListViewItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ListViewItemDataAutomationPeer::ListViewItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ListViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline MediaElementAutomationPeer::MediaElementAutomationPeer(Windows::UI::Xaml::Controls::MediaElement const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MediaElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline MediaPlayerElementAutomationPeer::MediaPlayerElementAutomationPeer(Windows::UI::Xaml::Controls::MediaPlayerElement const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MediaPlayerElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline MediaTransportControlsAutomationPeer::MediaTransportControlsAutomationPeer(Windows::UI::Xaml::Controls::MediaTransportControls const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MediaTransportControlsAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline MenuBarAutomationPeer::MenuBarAutomationPeer(Windows::UI::Xaml::Controls::MenuBar const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MenuBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory>([&](auto&& f) { return f.CreateInstance(owner, baseInterface, innerInterface); });
}

inline MenuBarItemAutomationPeer::MenuBarItemAutomationPeer(Windows::UI::Xaml::Controls::MenuBarItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MenuBarItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstance(owner, baseInterface, innerInterface); });
}

inline MenuFlyoutItemAutomationPeer::MenuFlyoutItemAutomationPeer(Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline MenuFlyoutPresenterAutomationPeer::MenuFlyoutPresenterAutomationPeer(Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MenuFlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline NavigationViewItemAutomationPeer::NavigationViewItemAutomationPeer(Windows::UI::Xaml::Controls::NavigationViewItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<NavigationViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline PasswordBoxAutomationPeer::PasswordBoxAutomationPeer(Windows::UI::Xaml::Controls::PasswordBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PasswordBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline PersonPictureAutomationPeer::PersonPictureAutomationPeer(Windows::UI::Xaml::Controls::PersonPicture const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PersonPictureAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline PivotAutomationPeer::PivotAutomationPeer(Windows::UI::Xaml::Controls::Pivot const& owner) :
    PivotAutomationPeer(impl::call_factory<PivotAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner); }))
{}

inline PivotItemAutomationPeer::PivotItemAutomationPeer(Windows::UI::Xaml::Controls::PivotItem const& owner) :
    PivotItemAutomationPeer(impl::call_factory<PivotItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner); }))
{}

inline PivotItemDataAutomationPeer::PivotItemDataAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer const& parent) :
    PivotItemDataAutomationPeer(impl::call_factory<PivotItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent); }))
{}

inline ProgressBarAutomationPeer::ProgressBarAutomationPeer(Windows::UI::Xaml::Controls::ProgressBar const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ProgressBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ProgressRingAutomationPeer::ProgressRingAutomationPeer(Windows::UI::Xaml::Controls::ProgressRing const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ProgressRingAutomationPeer, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RadioButtonAutomationPeer::RadioButtonAutomationPeer(Windows::UI::Xaml::Controls::RadioButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RadioButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RangeBaseAutomationPeer::RangeBaseAutomationPeer(Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RatingControlAutomationPeer::RatingControlAutomationPeer(Windows::UI::Xaml::Controls::RatingControl const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RatingControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RepeatButtonAutomationPeer::RepeatButtonAutomationPeer(Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RepeatButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RichEditBoxAutomationPeer::RichEditBoxAutomationPeer(Windows::UI::Xaml::Controls::RichEditBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RichEditBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RichTextBlockAutomationPeer::RichTextBlockAutomationPeer(Windows::UI::Xaml::Controls::RichTextBlock const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RichTextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline RichTextBlockOverflowAutomationPeer::RichTextBlockOverflowAutomationPeer(Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RichTextBlockOverflowAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ScrollBarAutomationPeer::ScrollBarAutomationPeer(Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ScrollBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ScrollViewerAutomationPeer::ScrollViewerAutomationPeer(Windows::UI::Xaml::Controls::ScrollViewer const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ScrollViewerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline SearchBoxAutomationPeer::SearchBoxAutomationPeer(Windows::UI::Xaml::Controls::SearchBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SearchBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline SelectorAutomationPeer::SelectorAutomationPeer(Windows::UI::Xaml::Controls::Primitives::Selector const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline SelectorItemAutomationPeer::SelectorItemAutomationPeer(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithParentAndItem(item, parent, baseInterface, innerInterface); });
}

inline SemanticZoomAutomationPeer::SemanticZoomAutomationPeer(Windows::UI::Xaml::Controls::SemanticZoom const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SemanticZoomAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline SettingsFlyoutAutomationPeer::SettingsFlyoutAutomationPeer(Windows::UI::Xaml::Controls::SettingsFlyout const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SettingsFlyoutAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline SliderAutomationPeer::SliderAutomationPeer(Windows::UI::Xaml::Controls::Slider const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline TextBlockAutomationPeer::TextBlockAutomationPeer(Windows::UI::Xaml::Controls::TextBlock const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline TextBoxAutomationPeer::TextBoxAutomationPeer(Windows::UI::Xaml::Controls::TextBox const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TextBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ThumbAutomationPeer::ThumbAutomationPeer(Windows::UI::Xaml::Controls::Primitives::Thumb const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ThumbAutomationPeer, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline TimePickerAutomationPeer::TimePickerAutomationPeer(Windows::UI::Xaml::Controls::TimePicker const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TimePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ToggleButtonAutomationPeer::ToggleButtonAutomationPeer(Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ToggleMenuFlyoutItemAutomationPeer::ToggleMenuFlyoutItemAutomationPeer(Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ToggleMenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline ToggleSwitchAutomationPeer::ToggleSwitchAutomationPeer(Windows::UI::Xaml::Controls::ToggleSwitch const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ToggleSwitchAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline TreeViewItemAutomationPeer::TreeViewItemAutomationPeer(Windows::UI::Xaml::Controls::TreeViewItem const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TreeViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

inline TreeViewListAutomationPeer::TreeViewListAutomationPeer(Windows::UI::Xaml::Controls::TreeViewList const& owner)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<TreeViewListAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory>([&](auto&& f) { return f.CreateInstanceWithOwner(owner, baseInterface, innerInterface); });
}

template <typename D> Windows::Foundation::IInspectable IAutomationPeerOverridesT<D>::GetPatternCore(Windows::UI::Xaml::Automation::Peers::PatternInterface const& patternInterface) const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetPatternCore(patternInterface);
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetAcceleratorKeyCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetAcceleratorKeyCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetAccessKeyCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetAccessKeyCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationControlType IAutomationPeerOverridesT<D>::GetAutomationControlTypeCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetAutomationControlTypeCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetAutomationIdCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetAutomationIdCore();
}

template <typename D> Windows::Foundation::Rect IAutomationPeerOverridesT<D>::GetBoundingRectangleCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetBoundingRectangleCore();
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeer> IAutomationPeerOverridesT<D>::GetChildrenCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetChildrenCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetClassNameCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetClassNameCore();
}

template <typename D> Windows::Foundation::Point IAutomationPeerOverridesT<D>::GetClickablePointCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetClickablePointCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetHelpTextCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetHelpTextCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetItemStatusCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetItemStatusCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetItemTypeCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetItemTypeCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer IAutomationPeerOverridesT<D>::GetLabeledByCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetLabeledByCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetLocalizedControlTypeCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetLocalizedControlTypeCore();
}

template <typename D> hstring IAutomationPeerOverridesT<D>::GetNameCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetNameCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationOrientation IAutomationPeerOverridesT<D>::GetOrientationCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetOrientationCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::HasKeyboardFocusCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().HasKeyboardFocusCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsContentElementCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsContentElementCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsControlElementCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsControlElementCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsEnabledCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsEnabledCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsKeyboardFocusableCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsKeyboardFocusableCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsOffscreenCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsOffscreenCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsPasswordCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsPasswordCore();
}

template <typename D> bool IAutomationPeerOverridesT<D>::IsRequiredForFormCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().IsRequiredForFormCore();
}

template <typename D> void IAutomationPeerOverridesT<D>::SetFocusCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().SetFocusCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationPeer IAutomationPeerOverridesT<D>::GetPeerFromPointCore(Windows::Foundation::Point const& point) const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetPeerFromPointCore(point);
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting IAutomationPeerOverridesT<D>::GetLiveSettingCore() const
{
    return shim().template try_as<IAutomationPeerOverrides>().GetLiveSettingCore();
}

template <typename D> void IAutomationPeerOverrides2T<D>::ShowContextMenuCore() const
{
    return shim().template try_as<IAutomationPeerOverrides2>().ShowContextMenuCore();
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Automation::Peers::AutomationPeer> IAutomationPeerOverrides2T<D>::GetControlledPeersCore() const
{
    return shim().template try_as<IAutomationPeerOverrides2>().GetControlledPeersCore();
}

template <typename D> Windows::Foundation::IInspectable IAutomationPeerOverrides3T<D>::NavigateCore(Windows::UI::Xaml::Automation::Peers::AutomationNavigationDirection const& direction) const
{
    return shim().template try_as<IAutomationPeerOverrides3>().NavigateCore(direction);
}

template <typename D> Windows::Foundation::IInspectable IAutomationPeerOverrides3T<D>::GetElementFromPointCore(Windows::Foundation::Point const& pointInWindowCoordinates) const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetElementFromPointCore(pointInWindowCoordinates);
}

template <typename D> Windows::Foundation::IInspectable IAutomationPeerOverrides3T<D>::GetFocusedElementCore() const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetFocusedElementCore();
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> IAutomationPeerOverrides3T<D>::GetAnnotationsCore() const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetAnnotationsCore();
}

template <typename D> int32_t IAutomationPeerOverrides3T<D>::GetPositionInSetCore() const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetPositionInSetCore();
}

template <typename D> int32_t IAutomationPeerOverrides3T<D>::GetSizeOfSetCore() const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetSizeOfSetCore();
}

template <typename D> int32_t IAutomationPeerOverrides3T<D>::GetLevelCore() const
{
    return shim().template try_as<IAutomationPeerOverrides3>().GetLevelCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType IAutomationPeerOverrides4T<D>::GetLandmarkTypeCore() const
{
    return shim().template try_as<IAutomationPeerOverrides4>().GetLandmarkTypeCore();
}

template <typename D> hstring IAutomationPeerOverrides4T<D>::GetLocalizedLandmarkTypeCore() const
{
    return shim().template try_as<IAutomationPeerOverrides4>().GetLocalizedLandmarkTypeCore();
}

template <typename D> bool IAutomationPeerOverrides5T<D>::IsPeripheralCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().IsPeripheralCore();
}

template <typename D> bool IAutomationPeerOverrides5T<D>::IsDataValidForFormCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().IsDataValidForFormCore();
}

template <typename D> hstring IAutomationPeerOverrides5T<D>::GetFullDescriptionCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().GetFullDescriptionCore();
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> IAutomationPeerOverrides5T<D>::GetDescribedByCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().GetDescribedByCore();
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> IAutomationPeerOverrides5T<D>::GetFlowsToCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().GetFlowsToCore();
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Automation::Peers::AutomationPeer> IAutomationPeerOverrides5T<D>::GetFlowsFromCore() const
{
    return shim().template try_as<IAutomationPeerOverrides5>().GetFlowsFromCore();
}

template <typename D> int32_t IAutomationPeerOverrides6T<D>::GetCultureCore() const
{
    return shim().template try_as<IAutomationPeerOverrides6>().GetCultureCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel IAutomationPeerOverrides8T<D>::GetHeadingLevelCore() const
{
    return shim().template try_as<IAutomationPeerOverrides8>().GetHeadingLevelCore();
}

template <typename D> bool IAutomationPeerOverrides9T<D>::IsDialogCore() const
{
    return shim().template try_as<IAutomationPeerOverrides9>().IsDialogCore();
}

template <typename D> Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer IItemsControlAutomationPeerOverrides2T<D>::OnCreateItemAutomationPeer(Windows::Foundation::IInspectable const& item) const
{
    return shim().template try_as<IItemsControlAutomationPeerOverrides2>().OnCreateItemAutomationPeer(item);
}

template <typename D, typename... Interfaces>
struct AppBarAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::Automation::Provider::IWindowProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = AppBarAutomationPeer;

protected:
    AppBarAutomationPeerT(Windows::UI::Xaml::Controls::AppBar const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct AppBarButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = AppBarButtonAutomationPeer;

protected:
    AppBarButtonAutomationPeerT(Windows::UI::Xaml::Controls::AppBarButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct AppBarToggleButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = AppBarToggleButtonAutomationPeer;

protected:
    AppBarToggleButtonAutomationPeerT(Windows::UI::Xaml::Controls::AppBarToggleButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct AutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = AutomationPeer;

protected:
    AutomationPeerT()
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ButtonAutomationPeer;

protected:
    ButtonAutomationPeerT(Windows::UI::Xaml::Controls::Button const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ButtonBaseAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ButtonBaseAutomationPeer;

protected:
    ButtonBaseAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::ButtonBase const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CalendarDatePickerAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::Automation::Provider::IValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = CalendarDatePickerAutomationPeer;

protected:
    CalendarDatePickerAutomationPeerT(Windows::UI::Xaml::Controls::CalendarDatePicker const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CaptureElementAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = CaptureElementAutomationPeer;

protected:
    CaptureElementAutomationPeerT(Windows::UI::Xaml::Controls::CaptureElement const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CheckBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = CheckBoxAutomationPeer;

protected:
    CheckBoxAutomationPeerT(Windows::UI::Xaml::Controls::CheckBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorPickerSliderAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ColorPickerSliderAutomationPeer;

protected:
    ColorPickerSliderAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::ColorPickerSlider const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ColorSpectrumAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ColorSpectrumAutomationPeer;

protected:
    ColorSpectrumAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::ColorSpectrum const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer, Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ComboBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::Automation::Provider::IValueProvider, Windows::UI::Xaml::Automation::Provider::IWindowProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = ComboBoxAutomationPeer;

protected:
    ComboBoxAutomationPeerT(Windows::UI::Xaml::Controls::ComboBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ComboBoxItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ComboBoxItemAutomationPeer;

protected:
    ComboBoxItemAutomationPeerT(Windows::UI::Xaml::Controls::ComboBoxItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ComboBoxItemDataAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ComboBoxItemDataAutomationPeer;

protected:
    ComboBoxItemDataAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct DatePickerAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = DatePickerAutomationPeer;

protected:
    DatePickerAutomationPeerT(Windows::UI::Xaml::Controls::DatePicker const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlipViewAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = FlipViewAutomationPeer;

protected:
    FlipViewAutomationPeerT(Windows::UI::Xaml::Controls::FlipView const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlipViewItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = FlipViewItemAutomationPeer;

protected:
    FlipViewItemAutomationPeerT(Windows::UI::Xaml::Controls::FlipViewItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlipViewItemDataAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = FlipViewItemDataAutomationPeer;

protected:
    FlipViewItemDataAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FlyoutPresenterAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = FlyoutPresenterAutomationPeer;

protected:
    FlyoutPresenterAutomationPeerT(Windows::UI::Xaml::Controls::FlyoutPresenter const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct FrameworkElementAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = FrameworkElementAutomationPeer;

protected:
    FrameworkElementAutomationPeerT(Windows::UI::Xaml::FrameworkElement const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GridViewAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = GridViewAutomationPeer;

protected:
    GridViewAutomationPeerT(Windows::UI::Xaml::Controls::GridView const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GridViewHeaderItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = GridViewHeaderItemAutomationPeer;

protected:
    GridViewHeaderItemAutomationPeerT(Windows::UI::Xaml::Controls::GridViewHeaderItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GridViewItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = GridViewItemAutomationPeer;

protected:
    GridViewItemAutomationPeerT(Windows::UI::Xaml::Controls::GridViewItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GridViewItemDataAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = GridViewItemDataAutomationPeer;

protected:
    GridViewItemDataAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct GroupItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = GroupItemAutomationPeer;

protected:
    GroupItemAutomationPeerT(Windows::UI::Xaml::Controls::GroupItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct HubAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::HubAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = HubAutomationPeer;

protected:
    HubAutomationPeerT(Windows::UI::Xaml::Controls::Hub const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::HubAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct HubSectionAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = HubSectionAutomationPeer;

protected:
    HubSectionAutomationPeerT(Windows::UI::Xaml::Controls::HubSection const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct HyperlinkButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = HyperlinkButtonAutomationPeer;

protected:
    HyperlinkButtonAutomationPeerT(Windows::UI::Xaml::Controls::HyperlinkButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ImageAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ImageAutomationPeer;

protected:
    ImageAutomationPeerT(Windows::UI::Xaml::Controls::Image const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer, Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ItemAutomationPeer;

protected:
    ItemAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ItemsControlAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = ItemsControlAutomationPeer;

protected:
    ItemsControlAutomationPeerT(Windows::UI::Xaml::Controls::ItemsControl const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = ListBoxAutomationPeer;

protected:
    ListBoxAutomationPeerT(Windows::UI::Xaml::Controls::ListBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListBoxItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListBoxItemAutomationPeer;

protected:
    ListBoxItemAutomationPeerT(Windows::UI::Xaml::Controls::ListBoxItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListBoxItemDataAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListBoxItemDataAutomationPeer;

protected:
    ListBoxItemDataAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = ListViewAutomationPeer;

protected:
    ListViewAutomationPeerT(Windows::UI::Xaml::Controls::ListView const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewBaseAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IDropTargetProvider, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = ListViewBaseAutomationPeer;

protected:
    ListViewBaseAutomationPeerT(Windows::UI::Xaml::Controls::ListViewBase const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewBaseHeaderItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListViewBaseHeaderItemAutomationPeer;

protected:
    ListViewBaseHeaderItemAutomationPeerT(Windows::UI::Xaml::Controls::ListViewBaseHeaderItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewHeaderItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListViewHeaderItemAutomationPeer;

protected:
    ListViewHeaderItemAutomationPeerT(Windows::UI::Xaml::Controls::ListViewHeaderItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListViewItemAutomationPeer;

protected:
    ListViewItemAutomationPeerT(Windows::UI::Xaml::Controls::ListViewItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ListViewItemDataAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollItemProvider, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ListViewItemDataAutomationPeer;

protected:
    ListViewItemDataAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MediaElementAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MediaElementAutomationPeer;

protected:
    MediaElementAutomationPeerT(Windows::UI::Xaml::Controls::MediaElement const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MediaPlayerElementAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MediaPlayerElementAutomationPeer;

protected:
    MediaPlayerElementAutomationPeerT(Windows::UI::Xaml::Controls::MediaPlayerElement const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MediaTransportControlsAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MediaTransportControlsAutomationPeer;

protected:
    MediaTransportControlsAutomationPeerT(Windows::UI::Xaml::Controls::MediaTransportControls const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MenuBarAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MenuBarAutomationPeer;

protected:
    MenuBarAutomationPeerT(Windows::UI::Xaml::Controls::MenuBar const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory>([&](auto&& f) { f.CreateInstance(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MenuBarItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MenuBarItemAutomationPeer;

protected:
    MenuBarItemAutomationPeerT(Windows::UI::Xaml::Controls::MenuBarItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstance(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MenuFlyoutItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = MenuFlyoutItemAutomationPeer;

protected:
    MenuFlyoutItemAutomationPeerT(Windows::UI::Xaml::Controls::MenuFlyoutItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MenuFlyoutPresenterAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = MenuFlyoutPresenterAutomationPeer;

protected:
    MenuFlyoutPresenterAutomationPeerT(Windows::UI::Xaml::Controls::MenuFlyoutPresenter const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer, Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct NavigationViewItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = NavigationViewItemAutomationPeer;

protected:
    NavigationViewItemAutomationPeerT(Windows::UI::Xaml::Controls::NavigationViewItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PasswordBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = PasswordBoxAutomationPeer;

protected:
    PasswordBoxAutomationPeerT(Windows::UI::Xaml::Controls::PasswordBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PersonPictureAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = PersonPictureAutomationPeer;

protected:
    PersonPictureAutomationPeerT(Windows::UI::Xaml::Controls::PersonPicture const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer, Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ProgressBarAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ProgressBarAutomationPeer;

protected:
    ProgressBarAutomationPeerT(Windows::UI::Xaml::Controls::ProgressBar const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ProgressRingAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ProgressRingAutomationPeer;

protected:
    ProgressRingAutomationPeerT(Windows::UI::Xaml::Controls::ProgressRing const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer, Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RadioButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RadioButtonAutomationPeer;

protected:
    RadioButtonAutomationPeerT(Windows::UI::Xaml::Controls::RadioButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RangeBaseAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RangeBaseAutomationPeer;

protected:
    RangeBaseAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::RangeBase const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RatingControlAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RatingControlAutomationPeer;

protected:
    RatingControlAutomationPeerT(Windows::UI::Xaml::Controls::RatingControl const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RepeatButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IInvokeProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RepeatButtonAutomationPeer;

protected:
    RepeatButtonAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::RepeatButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RichEditBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RichEditBoxAutomationPeer;

protected:
    RichEditBoxAutomationPeerT(Windows::UI::Xaml::Controls::RichEditBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RichTextBlockAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RichTextBlockAutomationPeer;

protected:
    RichTextBlockAutomationPeerT(Windows::UI::Xaml::Controls::RichTextBlock const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RichTextBlockOverflowAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = RichTextBlockOverflowAutomationPeer;

protected:
    RichTextBlockOverflowAutomationPeerT(Windows::UI::Xaml::Controls::RichTextBlockOverflow const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ScrollBarAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ScrollBarAutomationPeer;

protected:
    ScrollBarAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::ScrollBar const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer, Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ScrollViewerAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IScrollProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ScrollViewerAutomationPeer;

protected:
    ScrollViewerAutomationPeerT(Windows::UI::Xaml::Controls::ScrollViewer const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SearchBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = SearchBoxAutomationPeer;

protected:
    SearchBoxAutomationPeerT(Windows::UI::Xaml::Controls::SearchBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SelectorAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = SelectorAutomationPeer;

protected:
    SelectorAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::Selector const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SelectorItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::ISelectionItemProvider, Windows::UI::Xaml::Automation::Provider::IVirtualizedItemProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = SelectorItemAutomationPeer;

protected:
    SelectorItemAutomationPeerT(Windows::Foundation::IInspectable const& item, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer const& parent)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithParentAndItem(item, parent, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SemanticZoomAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = SemanticZoomAutomationPeer;

protected:
    SemanticZoomAutomationPeerT(Windows::UI::Xaml::Controls::SemanticZoom const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SettingsFlyoutAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = SettingsFlyoutAutomationPeer;

protected:
    SettingsFlyoutAutomationPeerT(Windows::UI::Xaml::Controls::SettingsFlyout const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SliderAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Provider::IRangeValueProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = SliderAutomationPeer;

protected:
    SliderAutomationPeerT(Windows::UI::Xaml::Controls::Slider const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer, Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TextBlockAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = TextBlockAutomationPeer;

protected:
    TextBlockAutomationPeerT(Windows::UI::Xaml::Controls::TextBlock const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TextBoxAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = TextBoxAutomationPeer;

protected:
    TextBoxAutomationPeerT(Windows::UI::Xaml::Controls::TextBox const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ThumbAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ThumbAutomationPeer;

protected:
    ThumbAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::Thumb const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer, Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TimePickerAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = TimePickerAutomationPeer;

protected:
    TimePickerAutomationPeerT(Windows::UI::Xaml::Controls::TimePicker const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ToggleButtonAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ToggleButtonAutomationPeer;

protected:
    ToggleButtonAutomationPeerT(Windows::UI::Xaml::Controls::Primitives::ToggleButton const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ToggleMenuFlyoutItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ToggleMenuFlyoutItemAutomationPeer;

protected:
    ToggleMenuFlyoutItemAutomationPeerT(Windows::UI::Xaml::Controls::ToggleMenuFlyoutItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ToggleSwitchAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Provider::IToggleProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = ToggleSwitchAutomationPeer;

protected:
    ToggleSwitchAutomationPeerT(Windows::UI::Xaml::Controls::ToggleSwitch const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer, Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TreeViewItemAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Provider::IExpandCollapseProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>
{
    using composable = TreeViewItemAutomationPeer;

protected:
    TreeViewItemAutomationPeerT(Windows::UI::Xaml::Controls::TreeViewItem const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct TreeViewListAutomationPeerT :
    implements<D, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer, Windows::UI::Xaml::Automation::Peers::IAutomationPeer2, Windows::UI::Xaml::Automation::Peers::IAutomationPeer3, Windows::UI::Xaml::Automation::Peers::IAutomationPeer4, Windows::UI::Xaml::Automation::Peers::IAutomationPeer5, Windows::UI::Xaml::Automation::Peers::IAutomationPeer6, Windows::UI::Xaml::Automation::Peers::IAutomationPeer7, Windows::UI::Xaml::Automation::Peers::IAutomationPeer8, Windows::UI::Xaml::Automation::Peers::IAutomationPeer9, Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected, Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2, Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer, Windows::UI::Xaml::Automation::Provider::IItemContainerProvider, Windows::UI::Xaml::Automation::Provider::ISelectionProvider, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer, Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer, Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer, Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer, Windows::UI::Xaml::Automation::Peers::AutomationPeer, Windows::UI::Xaml::DependencyObject>,
    Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverridesT<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8T<D>, Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9T<D>, Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2T<D>
{
    using composable = TreeViewListAutomationPeer;

protected:
    TreeViewListAutomationPeerT(Windows::UI::Xaml::Controls::TreeViewList const& owner)
    {
        impl::call_factory<Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer, Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory>([&](auto&& f) { f.CreateInstanceWithOwner(owner, *this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAppBarToggleButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutoSuggestBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeer9> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerAnnotationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerOverrides9> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerProtected> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IAutomationPeerStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IButtonBaseAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICalendarDatePickerAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICaptureElementAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ICheckBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IColorPickerSliderAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IColorSpectrumAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IComboBoxItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IDatePickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlipViewItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFlyoutPresenterAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IFrameworkElementAutomationPeerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewHeaderItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGridViewItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IGroupItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHubAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHubSectionAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IHyperlinkButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IImageAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IInkToolbarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeer2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IItemsControlAutomationPeerOverrides2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListBoxItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListPickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewBaseHeaderItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewHeaderItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IListViewItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ILoopingSelectorItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMapControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaElementAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaPlayerElementAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMediaTransportControlsAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuBarItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IMenuFlyoutPresenterAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::INavigationViewItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPasswordBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPersonPictureAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IPivotItemDataAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IProgressBarAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IProgressRingAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRadioButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRangeBaseAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRatingControlAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRepeatButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichEditBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IRichTextBlockOverflowAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IScrollBarAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IScrollViewerAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISearchBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISelectorItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISemanticZoomAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISettingsFlyoutAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ISliderAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITextBlockAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITextBoxAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IThumbAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITimePickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleButtonAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleMenuFlyoutItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::IToggleSwitchAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewItemAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ITreeViewListAutomationPeerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AppBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AppBarButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AppBarToggleButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AutoSuggestBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::AutomationPeerAnnotation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ButtonBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::CalendarDatePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::CaptureElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::CheckBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ColorPickerSliderAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ColorSpectrumAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ComboBoxItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::DatePickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::FlipViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::FlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::FrameworkElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::GridViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::GridViewHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::GridViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::GroupItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::HubAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::HubSectionAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::HyperlinkButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ImageAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::InkToolbarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::InkToolbarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ItemsControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListBoxItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListPickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListPickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewBaseHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewHeaderItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ListViewItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::LoopingSelectorItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MapControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MapControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MediaElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MediaPlayerElementAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MediaTransportControlsAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MenuBarItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::MenuFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::NavigationViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PasswordBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PersonPictureAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PivotAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::PivotItemDataAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ProgressBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ProgressRingAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RadioButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RangeBaseAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RatingControlAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RepeatButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RichEditBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::RichTextBlockOverflowAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ScrollBarAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ScrollViewerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SearchBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SelectorAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SelectorItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SemanticZoomAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SettingsFlyoutAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::SliderAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TextBlockAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TextBoxAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ThumbAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerFlyoutPresenterAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TimePickerFlyoutPresenterAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ToggleButtonAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ToggleMenuFlyoutItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::ToggleSwitchAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewItemAutomationPeer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::Peers::TreeViewListAutomationPeer> {};

}
