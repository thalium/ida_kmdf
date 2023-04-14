// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.Peers.2.h"
#include "winrt/impl/Windows.UI.Xaml.Automation.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAnnotationPatternIdentifiersStatics<D>::AnnotationTypeIdProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics)->get_AnnotationTypeIdProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAnnotationPatternIdentifiersStatics<D>::AnnotationTypeNameProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics)->get_AnnotationTypeNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAnnotationPatternIdentifiersStatics<D>::AuthorProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics)->get_AuthorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAnnotationPatternIdentifiersStatics<D>::DateTimeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics)->get_DateTimeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAnnotationPatternIdentifiersStatics<D>::TargetProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics)->get_TargetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AnnotationType consume_Windows_UI_Xaml_Automation_IAutomationAnnotation<D>::Type() const
{
    Windows::UI::Xaml::Automation::AnnotationType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotation)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationAnnotation<D>::Type(Windows::UI::Xaml::Automation::AnnotationType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotation)->put_Type(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Automation_IAutomationAnnotation<D>::Element() const
{
    Windows::UI::Xaml::UIElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotation)->get_Element(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationAnnotation<D>::Element(Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotation)->put_Element(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Automation::AutomationAnnotation consume_Windows_UI_Xaml_Automation_IAutomationAnnotationFactory<D>::CreateInstance(Windows::UI::Xaml::Automation::AnnotationType const& type) const
{
    Windows::UI::Xaml::Automation::AutomationAnnotation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotationFactory)->CreateInstance(get_abi(type), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationAnnotation consume_Windows_UI_Xaml_Automation_IAutomationAnnotationFactory<D>::CreateWithElementParameter(Windows::UI::Xaml::Automation::AnnotationType const& type, Windows::UI::Xaml::UIElement const& element) const
{
    Windows::UI::Xaml::Automation::AutomationAnnotation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotationFactory)->CreateWithElementParameter(get_abi(type), get_abi(element), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationAnnotationStatics<D>::TypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotationStatics)->get_TypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationAnnotationStatics<D>::ElementProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationAnnotationStatics)->get_ElementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::AcceleratorKeyProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_AcceleratorKeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::AccessKeyProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_AccessKeyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::AutomationIdProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_AutomationIdProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::BoundingRectangleProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_BoundingRectangleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::ClassNameProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_ClassNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::ClickablePointProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_ClickablePointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::ControlTypeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_ControlTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::HasKeyboardFocusProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_HasKeyboardFocusProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::HelpTextProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_HelpTextProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsContentElementProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsContentElementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsControlElementProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsControlElementProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsEnabledProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsKeyboardFocusableProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsKeyboardFocusableProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsOffscreenProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsOffscreenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsPasswordProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsPasswordProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::IsRequiredForFormProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_IsRequiredForFormProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::ItemStatusProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_ItemStatusProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::ItemTypeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_ItemTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::LabeledByProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_LabeledByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::LocalizedControlTypeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_LocalizedControlTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::NameProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_NameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::OrientationProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_OrientationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics<D>::LiveSettingProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics)->get_LiveSettingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics2<D>::ControlledPeersProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2)->get_ControlledPeersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics3<D>::PositionInSetProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3)->get_PositionInSetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics3<D>::SizeOfSetProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3)->get_SizeOfSetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics3<D>::LevelProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3)->get_LevelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics3<D>::AnnotationsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3)->get_AnnotationsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics4<D>::LandmarkTypeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4)->get_LandmarkTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics4<D>::LocalizedLandmarkTypeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4)->get_LocalizedLandmarkTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::IsPeripheralProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_IsPeripheralProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::IsDataValidForFormProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_IsDataValidForFormProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::FullDescriptionProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_FullDescriptionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::DescribedByProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_DescribedByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::FlowsToProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_FlowsToProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics5<D>::FlowsFromProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5)->get_FlowsFromProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics6<D>::CultureProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6)->get_CultureProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics7<D>::HeadingLevelProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7)->get_HeadingLevelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IAutomationElementIdentifiersStatics8<D>::IsDialogProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8)->get_IsDialogProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::AcceleratorKeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_AcceleratorKeyProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetAcceleratorKey(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetAcceleratorKey(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetAcceleratorKey(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetAcceleratorKey(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::AccessKeyProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_AccessKeyProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetAccessKey(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetAccessKey(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetAccessKey(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetAccessKey(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::AutomationIdProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_AutomationIdProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetAutomationId(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetAutomationId(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetAutomationId(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetAutomationId(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::HelpTextProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_HelpTextProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetHelpText(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetHelpText(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetHelpText(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetHelpText(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::IsRequiredForFormProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_IsRequiredForFormProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetIsRequiredForForm(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetIsRequiredForForm(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetIsRequiredForForm(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetIsRequiredForForm(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::ItemStatusProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_ItemStatusProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetItemStatus(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetItemStatus(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetItemStatus(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetItemStatus(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::ItemTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_ItemTypeProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetItemType(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetItemType(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetItemType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetItemType(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::LabeledByProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_LabeledByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::UIElement consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetLabeledBy(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::UIElement result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetLabeledBy(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetLabeledBy(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::UIElement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetLabeledBy(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::NameProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_NameProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetName(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetName(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetName(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetName(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::LiveSettingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->get_LiveSettingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::GetLiveSetting(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->GetLiveSetting(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics<D>::SetLiveSetting(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics)->SetLiveSetting(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics2<D>::AccessibilityViewProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2)->get_AccessibilityViewProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AccessibilityView consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics2<D>::GetAccessibilityView(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AccessibilityView result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2)->GetAccessibilityView(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics2<D>::SetAccessibilityView(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AccessibilityView const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2)->SetAccessibilityView(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics2<D>::ControlledPeersProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2)->get_ControlledPeersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement> consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics2<D>::GetControlledPeers(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2)->GetControlledPeers(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::PositionInSetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->get_PositionInSetProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::GetPositionInSet(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->GetPositionInSet(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::SetPositionInSet(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->SetPositionInSet(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::SizeOfSetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->get_SizeOfSetProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::GetSizeOfSet(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->GetSizeOfSet(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::SetSizeOfSet(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->SetSizeOfSet(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::LevelProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->get_LevelProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::GetLevel(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->GetLevel(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::SetLevel(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->SetLevel(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::AnnotationsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->get_AnnotationsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::AutomationAnnotation> consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics3<D>::GetAnnotations(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::AutomationAnnotation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3)->GetAnnotations(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::LandmarkTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->get_LandmarkTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::GetLandmarkType(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->GetLandmarkType(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::SetLandmarkType(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->SetLandmarkType(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::LocalizedLandmarkTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->get_LocalizedLandmarkTypeProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::GetLocalizedLandmarkType(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->GetLocalizedLandmarkType(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics4<D>::SetLocalizedLandmarkType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4)->SetLocalizedLandmarkType(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::IsPeripheralProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_IsPeripheralProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetIsPeripheral(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetIsPeripheral(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::SetIsPeripheral(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->SetIsPeripheral(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::IsDataValidForFormProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_IsDataValidForFormProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetIsDataValidForForm(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetIsDataValidForForm(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::SetIsDataValidForForm(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->SetIsDataValidForForm(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::FullDescriptionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_FullDescriptionProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetFullDescription(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetFullDescription(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::SetFullDescription(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->SetFullDescription(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::LocalizedControlTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_LocalizedControlTypeProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetLocalizedControlType(Windows::UI::Xaml::DependencyObject const& element) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetLocalizedControlType(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::SetLocalizedControlType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->SetLocalizedControlType(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::DescribedByProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_DescribedByProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetDescribedBy(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetDescribedBy(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::FlowsToProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_FlowsToProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetFlowsTo(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetFlowsTo(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::FlowsFromProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->get_FlowsFromProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics5<D>::GetFlowsFrom(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5)->GetFlowsFrom(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics6<D>::CultureProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6)->get_CultureProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics6<D>::GetCulture(Windows::UI::Xaml::DependencyObject const& element) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6)->GetCulture(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics6<D>::SetCulture(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6)->SetCulture(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics7<D>::HeadingLevelProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7)->get_HeadingLevelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics7<D>::GetHeadingLevel(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7)->GetHeadingLevel(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics7<D>::SetHeadingLevel(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7)->SetHeadingLevel(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics8<D>::IsDialogProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8)->get_IsDialogProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics8<D>::GetIsDialog(Windows::UI::Xaml::DependencyObject const& element) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8)->GetIsDialog(get_abi(element), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Automation_IAutomationPropertiesStatics8<D>::SetIsDialog(Windows::UI::Xaml::DependencyObject const& element, bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8)->SetIsDialog(get_abi(element), value));
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDockPatternIdentifiersStatics<D>::DockPositionProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics)->get_DockPositionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDragPatternIdentifiersStatics<D>::DropEffectProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics)->get_DropEffectProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDragPatternIdentifiersStatics<D>::DropEffectsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics)->get_DropEffectsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDragPatternIdentifiersStatics<D>::GrabbedItemsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics)->get_GrabbedItemsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDragPatternIdentifiersStatics<D>::IsGrabbedProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics)->get_IsGrabbedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDropTargetPatternIdentifiersStatics<D>::DropTargetEffectProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics)->get_DropTargetEffectProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IDropTargetPatternIdentifiersStatics<D>::DropTargetEffectsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics)->get_DropTargetEffectsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IExpandCollapsePatternIdentifiersStatics<D>::ExpandCollapseStateProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics)->get_ExpandCollapseStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridItemPatternIdentifiersStatics<D>::ColumnProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics)->get_ColumnProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridItemPatternIdentifiersStatics<D>::ColumnSpanProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics)->get_ColumnSpanProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridItemPatternIdentifiersStatics<D>::ContainingGridProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics)->get_ContainingGridProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridItemPatternIdentifiersStatics<D>::RowProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics)->get_RowProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridItemPatternIdentifiersStatics<D>::RowSpanProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics)->get_RowSpanProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridPatternIdentifiersStatics<D>::ColumnCountProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics)->get_ColumnCountProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IGridPatternIdentifiersStatics<D>::RowCountProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics)->get_RowCountProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IMultipleViewPatternIdentifiersStatics<D>::CurrentViewProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics)->get_CurrentViewProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IMultipleViewPatternIdentifiersStatics<D>::SupportedViewsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics)->get_SupportedViewsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::IsReadOnlyProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_IsReadOnlyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::LargeChangeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_LargeChangeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::MaximumProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_MaximumProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::MinimumProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_MinimumProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::SmallChangeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_SmallChangeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IRangeValuePatternIdentifiersStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::HorizontallyScrollableProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_HorizontallyScrollableProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::HorizontalScrollPercentProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_HorizontalScrollPercentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::HorizontalViewSizeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_HorizontalViewSizeProperty(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::NoScroll() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_NoScroll(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::VerticallyScrollableProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_VerticallyScrollableProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::VerticalScrollPercentProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_VerticalScrollPercentProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IScrollPatternIdentifiersStatics<D>::VerticalViewSizeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics)->get_VerticalViewSizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISelectionItemPatternIdentifiersStatics<D>::IsSelectedProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics)->get_IsSelectedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISelectionItemPatternIdentifiersStatics<D>::SelectionContainerProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics)->get_SelectionContainerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISelectionPatternIdentifiersStatics<D>::CanSelectMultipleProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics)->get_CanSelectMultipleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISelectionPatternIdentifiersStatics<D>::IsSelectionRequiredProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics)->get_IsSelectionRequiredProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISelectionPatternIdentifiersStatics<D>::SelectionProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics)->get_SelectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ISpreadsheetItemPatternIdentifiersStatics<D>::FormulaProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics)->get_FormulaProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::ExtendedPropertiesProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_ExtendedPropertiesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::FillColorProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_FillColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::FillPatternColorProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_FillPatternColorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::FillPatternStyleProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_FillPatternStyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::ShapeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_ShapeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::StyleIdProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_StyleIdProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IStylesPatternIdentifiersStatics<D>::StyleNameProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics)->get_StyleNameProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITableItemPatternIdentifiersStatics<D>::ColumnHeaderItemsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics)->get_ColumnHeaderItemsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITableItemPatternIdentifiersStatics<D>::RowHeaderItemsProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics)->get_RowHeaderItemsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITablePatternIdentifiersStatics<D>::ColumnHeadersProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics)->get_ColumnHeadersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITablePatternIdentifiersStatics<D>::RowHeadersProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics)->get_RowHeadersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITablePatternIdentifiersStatics<D>::RowOrColumnMajorProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics)->get_RowOrColumnMajorProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITogglePatternIdentifiersStatics<D>::ToggleStateProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics)->get_ToggleStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPattern2IdentifiersStatics<D>::CanZoomProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics)->get_CanZoomProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPattern2IdentifiersStatics<D>::ZoomLevelProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics)->get_ZoomLevelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPattern2IdentifiersStatics<D>::MaxZoomProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics)->get_MaxZoomProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPattern2IdentifiersStatics<D>::MinZoomProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics)->get_MinZoomProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPatternIdentifiersStatics<D>::CanMoveProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics)->get_CanMoveProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPatternIdentifiersStatics<D>::CanResizeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics)->get_CanResizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_ITransformPatternIdentifiersStatics<D>::CanRotateProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics)->get_CanRotateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IValuePatternIdentifiersStatics<D>::IsReadOnlyProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics)->get_IsReadOnlyProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IValuePatternIdentifiersStatics<D>::ValueProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics)->get_ValueProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::CanMaximizeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_CanMaximizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::CanMinimizeProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_CanMinimizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::IsModalProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_IsModalProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::IsTopmostProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_IsTopmostProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::WindowInteractionStateProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_WindowInteractionStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Automation::AutomationProperty consume_Windows_UI_Xaml_Automation_IWindowPatternIdentifiersStatics<D>::WindowVisualStateProperty() const
{
    Windows::UI::Xaml::Automation::AutomationProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics)->get_WindowVisualStateProperty(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_AnnotationTypeIdProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationTypeIdProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AnnotationTypeIdProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnnotationTypeNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationTypeNameProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AnnotationTypeNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthorProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AuthorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTimeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTimeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DateTimeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().TargetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationAnnotation> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationAnnotation>
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationAnnotationFactory> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationAnnotationFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::UI::Xaml::Automation::AnnotationType type, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationAnnotation), Windows::UI::Xaml::Automation::AnnotationType const&);
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationAnnotation>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Automation::AnnotationType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithElementParameter(Windows::UI::Xaml::Automation::AnnotationType type, void* element, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithElementParameter, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationAnnotation), Windows::UI::Xaml::Automation::AnnotationType const&, Windows::UI::Xaml::UIElement const&);
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationAnnotation>(this->shim().CreateWithElementParameter(*reinterpret_cast<Windows::UI::Xaml::Automation::AnnotationType const*>(&type), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationAnnotationStatics> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationAnnotationStatics>
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

    int32_t WINRT_CALL get_ElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>
{
    int32_t WINRT_CALL get_AcceleratorKeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceleratorKeyProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AcceleratorKeyProperty());
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
            WINRT_ASSERT_DECLARATION(AccessKeyProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AccessKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutomationIdProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationIdProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AutomationIdProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingRectangleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRectangleProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().BoundingRectangleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClassNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassNameProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ClassNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClickablePointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClickablePointProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ClickablePointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlTypeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ControlTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasKeyboardFocusProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasKeyboardFocusProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HasKeyboardFocusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HelpTextProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HelpTextProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HelpTextProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsContentElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsContentElementProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsContentElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsControlElementProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsControlElementProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsControlElementProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsKeyboardFocusableProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsKeyboardFocusableProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsKeyboardFocusableProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOffscreenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOffscreenProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsOffscreenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPasswordProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPasswordProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsPasswordProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequiredForFormProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequiredForFormProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsRequiredForFormProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemStatusProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemStatusProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ItemStatusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTypeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ItemTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LabeledByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LabeledByProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LabeledByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalizedControlTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalizedControlTypeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LocalizedControlTypeProperty());
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
            WINRT_ASSERT_DECLARATION(NameProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().NameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OrientationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientationProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().OrientationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LiveSettingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LiveSettingProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LiveSettingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2>
{
    int32_t WINRT_CALL get_ControlledPeersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlledPeersProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ControlledPeersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3>
{
    int32_t WINRT_CALL get_PositionInSetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionInSetProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().PositionInSetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SizeOfSetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeOfSetProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().SizeOfSetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LevelProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnnotationsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().AnnotationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4>
{
    int32_t WINRT_CALL get_LandmarkTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LandmarkTypeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LandmarkTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalizedLandmarkTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalizedLandmarkTypeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LocalizedLandmarkTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>
{
    int32_t WINRT_CALL get_IsPeripheralProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPeripheralProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsPeripheralProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDataValidForFormProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataValidForFormProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsDataValidForFormProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullDescriptionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullDescriptionProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FullDescriptionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DescribedByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DescribedByProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DescribedByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowsToProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowsToProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FlowsToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowsFromProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowsFromProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FlowsFromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6>
{
    int32_t WINRT_CALL get_CultureProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CultureProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CultureProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7>
{
    int32_t WINRT_CALL get_HeadingLevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingLevelProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HeadingLevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8>
{
    int32_t WINRT_CALL get_IsDialogProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDialogProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsDialogProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationProperties> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationProperties>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>
{
    int32_t WINRT_CALL get_AcceleratorKeyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceleratorKeyProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AcceleratorKeyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAcceleratorKey(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAcceleratorKey, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetAcceleratorKey(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAcceleratorKey(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAcceleratorKey, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetAcceleratorKey(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL GetAccessKey(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccessKey, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetAccessKey(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccessKey(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccessKey, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetAccessKey(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutomationIdProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomationIdProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AutomationIdProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAutomationId(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutomationId, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetAutomationId(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAutomationId(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAutomationId, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetAutomationId(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HelpTextProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HelpTextProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HelpTextProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHelpText(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHelpText, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetHelpText(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHelpText(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHelpText, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetHelpText(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRequiredForFormProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRequiredForFormProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsRequiredForFormProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsRequiredForForm(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsRequiredForForm, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetIsRequiredForForm(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsRequiredForForm(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsRequiredForForm, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetIsRequiredForForm(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemStatusProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemStatusProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemStatusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemStatus(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemStatus, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetItemStatus(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetItemStatus(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetItemStatus, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetItemStatus(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemType(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemType, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetItemType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetItemType(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetItemType, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetItemType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LabeledByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LabeledByProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LabeledByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLabeledBy(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLabeledBy, WINRT_WRAP(Windows::UI::Xaml::UIElement), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::UIElement>(this->shim().GetLabeledBy(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLabeledBy(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLabeledBy, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::UIElement const&);
            this->shim().SetLabeledBy(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&value));
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

    int32_t WINRT_CALL GetName(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetName, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetName(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetName(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetName, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetName(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LiveSettingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LiveSettingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LiveSettingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLiveSetting(void* element, Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLiveSetting, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting>(this->shim().GetLiveSetting(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLiveSetting(void* element, Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLiveSetting, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting const&);
            this->shim().SetLiveSetting(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>
{
    int32_t WINRT_CALL get_AccessibilityViewProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessibilityViewProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AccessibilityViewProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccessibilityView(void* element, Windows::UI::Xaml::Automation::Peers::AccessibilityView* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccessibilityView, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AccessibilityView), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AccessibilityView>(this->shim().GetAccessibilityView(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAccessibilityView(void* element, Windows::UI::Xaml::Automation::Peers::AccessibilityView value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAccessibilityView, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Automation::Peers::AccessibilityView const&);
            this->shim().SetAccessibilityView(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AccessibilityView const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlledPeersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlledPeersProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ControlledPeersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetControlledPeers(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControlledPeers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement>), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement>>(this->shim().GetControlledPeers(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>
{
    int32_t WINRT_CALL get_PositionInSetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionInSetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PositionInSetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPositionInSet(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPositionInSet, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetPositionInSet(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPositionInSet(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPositionInSet, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetPositionInSet(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SizeOfSetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeOfSetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SizeOfSetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSizeOfSet(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSizeOfSet, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetSizeOfSet(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSizeOfSet(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSizeOfSet, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetSizeOfSet(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LevelProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLevel(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLevel, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetLevel(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLevel(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLevel, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetLevel(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AnnotationsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnnotationsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AnnotationsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAnnotations(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnnotations, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::AutomationAnnotation>), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::AutomationAnnotation>>(this->shim().GetAnnotations(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>
{
    int32_t WINRT_CALL get_LandmarkTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LandmarkTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LandmarkTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLandmarkType(void* element, Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLandmarkType, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType>(this->shim().GetLandmarkType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLandmarkType(void* element, Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLandmarkType, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType const&);
            this->shim().SetLandmarkType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalizedLandmarkTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalizedLandmarkTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocalizedLandmarkTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedLandmarkType(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedLandmarkType, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetLocalizedLandmarkType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLocalizedLandmarkType(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLocalizedLandmarkType, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetLocalizedLandmarkType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>
{
    int32_t WINRT_CALL get_IsPeripheralProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPeripheralProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsPeripheralProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsPeripheral(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsPeripheral, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetIsPeripheral(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsPeripheral(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsPeripheral, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetIsPeripheral(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDataValidForFormProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataValidForFormProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsDataValidForFormProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsDataValidForForm(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsDataValidForForm, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetIsDataValidForForm(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsDataValidForForm(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsDataValidForForm, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetIsDataValidForForm(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullDescriptionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullDescriptionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FullDescriptionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFullDescription(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFullDescription, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetFullDescription(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetFullDescription(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetFullDescription, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetFullDescription(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalizedControlTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalizedControlTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocalizedControlTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalizedControlType(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalizedControlType, WINRT_WRAP(hstring), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<hstring>(this->shim().GetLocalizedControlType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLocalizedControlType(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLocalizedControlType, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, hstring const&);
            this->shim().SetLocalizedControlType(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DescribedByProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DescribedByProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DescribedByProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDescribedBy(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDescribedBy, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>>(this->shim().GetDescribedBy(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowsToProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowsToProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FlowsToProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlowsTo(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlowsTo, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>>(this->shim().GetFlowsTo(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlowsFromProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlowsFromProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FlowsFromProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFlowsFrom(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFlowsFrom, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>>(this->shim().GetFlowsFrom(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6>
{
    int32_t WINRT_CALL get_CultureProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CultureProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CultureProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCulture(void* element, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCulture, WINRT_WRAP(int32_t), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<int32_t>(this->shim().GetCulture(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCulture(void* element, int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCulture, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, int32_t);
            this->shim().SetCulture(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7>
{
    int32_t WINRT_CALL get_HeadingLevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingLevelProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HeadingLevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHeadingLevel(void* element, Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHeadingLevel, WINRT_WRAP(Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel>(this->shim().GetHeadingLevel(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetHeadingLevel(void* element, Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetHeadingLevel, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel const&);
            this->shim().SetHeadingLevel(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8>
{
    int32_t WINRT_CALL get_IsDialogProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDialogProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsDialogProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsDialog(void* element, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsDialog, WINRT_WRAP(bool), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<bool>(this->shim().GetIsDialog(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIsDialog(void* element, bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIsDialog, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, bool);
            this->shim().SetIsDialog(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IAutomationProperty> : produce_base<D, Windows::UI::Xaml::Automation::IAutomationProperty>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDockPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IDockPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_DockPositionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DockPositionProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DockPositionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDragPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IDragPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_DropEffectProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffectProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DropEffectProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropEffectsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropEffectsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DropEffectsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GrabbedItemsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GrabbedItemsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().GrabbedItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGrabbedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGrabbedProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsGrabbedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_DropTargetEffectProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropTargetEffectProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DropTargetEffectProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DropTargetEffectsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DropTargetEffectsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().DropTargetEffectsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ExpandCollapseStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpandCollapseStateProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ExpandCollapseStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ColumnProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ColumnProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColumnSpanProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnSpanProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ColumnSpanProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContainingGridProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainingGridProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ContainingGridProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowSpanProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowSpanProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowSpanProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IGridPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IGridPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ColumnCountProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnCountProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ColumnCountProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowCountProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowCountProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowCountProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_CurrentViewProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentViewProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CurrentViewProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedViewsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedViewsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().SupportedViewsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_IsReadOnlyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnlyProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsReadOnlyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LargeChangeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LargeChangeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().LargeChangeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaximumProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaximumProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().MaximumProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinimumProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinimumProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().MinimumProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmallChangeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallChangeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().SmallChangeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IScrollPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IScrollPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_HorizontallyScrollableProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontallyScrollableProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HorizontallyScrollableProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalScrollPercentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalScrollPercentProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HorizontalScrollPercentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalViewSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalViewSizeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().HorizontalViewSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NoScroll(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoScroll, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NoScroll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticallyScrollableProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticallyScrollableProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().VerticallyScrollableProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalScrollPercentProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalScrollPercentProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().VerticalScrollPercentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalViewSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalViewSizeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().VerticalViewSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_IsSelectedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectedProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsSelectedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionContainerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionContainerProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().SelectionContainerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_CanSelectMultipleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSelectMultipleProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanSelectMultipleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSelectionRequiredProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectionRequiredProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsSelectionRequiredProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().SelectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_FormulaProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormulaProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FormulaProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IStylesPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IStylesPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ExtendedPropertiesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedPropertiesProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ExtendedPropertiesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillColorProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FillColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillPatternColorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillPatternColorProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FillPatternColorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillPatternStyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillPatternStyleProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().FillPatternStyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShapeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShapeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ShapeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleIdProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleIdProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().StyleIdProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleNameProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleNameProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().StyleNameProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ColumnHeaderItemsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnHeaderItemsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ColumnHeaderItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowHeaderItemsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowHeaderItemsProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowHeaderItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITablePatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ITablePatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ColumnHeadersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnHeadersProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ColumnHeadersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowHeadersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowHeadersProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowHeadersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RowOrColumnMajorProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RowOrColumnMajorProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().RowOrColumnMajorProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITogglePatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ITogglePatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_ToggleStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleStateProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ToggleStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITransformPattern2Identifiers> : produce_base<D, Windows::UI::Xaml::Automation::ITransformPattern2Identifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics>
{
    int32_t WINRT_CALL get_CanZoomProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoomProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanZoomProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ZoomLevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxZoomProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxZoomProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().MaxZoomProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinZoomProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinZoomProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().MinZoomProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITransformPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::ITransformPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_CanMoveProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMoveProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanMoveProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanResizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanResizeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanResizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRotateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRotateProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanRotateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IValuePatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IValuePatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_IsReadOnlyProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnlyProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsReadOnlyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ValueProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().ValueProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IWindowPatternIdentifiers> : produce_base<D, Windows::UI::Xaml::Automation::IWindowPatternIdentifiers>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics> : produce_base<D, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>
{
    int32_t WINRT_CALL get_CanMaximizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMaximizeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanMaximizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanMinimizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMinimizeProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().CanMinimizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsModalProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsModalProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsModalProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTopmostProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTopmostProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().IsTopmostProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WindowInteractionStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowInteractionStateProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().WindowInteractionStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WindowVisualStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WindowVisualStateProperty, WINRT_WRAP(Windows::UI::Xaml::Automation::AutomationProperty));
            *value = detach_from<Windows::UI::Xaml::Automation::AutomationProperty>(this->shim().WindowVisualStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Automation {

inline Windows::UI::Xaml::Automation::AutomationProperty AnnotationPatternIdentifiers::AnnotationTypeIdProperty()
{
    return impl::call_factory<AnnotationPatternIdentifiers, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>([&](auto&& f) { return f.AnnotationTypeIdProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AnnotationPatternIdentifiers::AnnotationTypeNameProperty()
{
    return impl::call_factory<AnnotationPatternIdentifiers, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>([&](auto&& f) { return f.AnnotationTypeNameProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AnnotationPatternIdentifiers::AuthorProperty()
{
    return impl::call_factory<AnnotationPatternIdentifiers, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>([&](auto&& f) { return f.AuthorProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AnnotationPatternIdentifiers::DateTimeProperty()
{
    return impl::call_factory<AnnotationPatternIdentifiers, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>([&](auto&& f) { return f.DateTimeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AnnotationPatternIdentifiers::TargetProperty()
{
    return impl::call_factory<AnnotationPatternIdentifiers, Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics>([&](auto&& f) { return f.TargetProperty(); });
}

inline AutomationAnnotation::AutomationAnnotation() :
    AutomationAnnotation(impl::call_factory<AutomationAnnotation>([](auto&& f) { return f.template ActivateInstance<AutomationAnnotation>(); }))
{}

inline AutomationAnnotation::AutomationAnnotation(Windows::UI::Xaml::Automation::AnnotationType const& type) :
    AutomationAnnotation(impl::call_factory<AutomationAnnotation, Windows::UI::Xaml::Automation::IAutomationAnnotationFactory>([&](auto&& f) { return f.CreateInstance(type); }))
{}

inline AutomationAnnotation::AutomationAnnotation(Windows::UI::Xaml::Automation::AnnotationType const& type, Windows::UI::Xaml::UIElement const& element) :
    AutomationAnnotation(impl::call_factory<AutomationAnnotation, Windows::UI::Xaml::Automation::IAutomationAnnotationFactory>([&](auto&& f) { return f.CreateWithElementParameter(type, element); }))
{}

inline Windows::UI::Xaml::DependencyProperty AutomationAnnotation::TypeProperty()
{
    return impl::call_factory<AutomationAnnotation, Windows::UI::Xaml::Automation::IAutomationAnnotationStatics>([&](auto&& f) { return f.TypeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationAnnotation::ElementProperty()
{
    return impl::call_factory<AutomationAnnotation, Windows::UI::Xaml::Automation::IAutomationAnnotationStatics>([&](auto&& f) { return f.ElementProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::AcceleratorKeyProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.AcceleratorKeyProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::AccessKeyProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.AccessKeyProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::AutomationIdProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.AutomationIdProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::BoundingRectangleProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.BoundingRectangleProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ClassNameProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.ClassNameProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ClickablePointProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.ClickablePointProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ControlTypeProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.ControlTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::HasKeyboardFocusProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.HasKeyboardFocusProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::HelpTextProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.HelpTextProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsContentElementProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsContentElementProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsControlElementProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsControlElementProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsEnabledProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsEnabledProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsKeyboardFocusableProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsKeyboardFocusableProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsOffscreenProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsOffscreenProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsPasswordProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsPasswordProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsRequiredForFormProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.IsRequiredForFormProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ItemStatusProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.ItemStatusProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ItemTypeProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.ItemTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LabeledByProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.LabeledByProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LocalizedControlTypeProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.LocalizedControlTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::NameProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.NameProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::OrientationProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.OrientationProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LiveSettingProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics>([&](auto&& f) { return f.LiveSettingProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::ControlledPeersProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2>([&](auto&& f) { return f.ControlledPeersProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::PositionInSetProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3>([&](auto&& f) { return f.PositionInSetProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::SizeOfSetProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3>([&](auto&& f) { return f.SizeOfSetProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LevelProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3>([&](auto&& f) { return f.LevelProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::AnnotationsProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3>([&](auto&& f) { return f.AnnotationsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LandmarkTypeProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4>([&](auto&& f) { return f.LandmarkTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::LocalizedLandmarkTypeProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4>([&](auto&& f) { return f.LocalizedLandmarkTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsPeripheralProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.IsPeripheralProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsDataValidForFormProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.IsDataValidForFormProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::FullDescriptionProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.FullDescriptionProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::DescribedByProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.DescribedByProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::FlowsToProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.FlowsToProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::FlowsFromProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5>([&](auto&& f) { return f.FlowsFromProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::CultureProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6>([&](auto&& f) { return f.CultureProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::HeadingLevelProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7>([&](auto&& f) { return f.HeadingLevelProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty AutomationElementIdentifiers::IsDialogProperty()
{
    return impl::call_factory<AutomationElementIdentifiers, Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8>([&](auto&& f) { return f.IsDialogProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::AcceleratorKeyProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.AcceleratorKeyProperty(); });
}

inline hstring AutomationProperties::GetAcceleratorKey(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetAcceleratorKey(element); });
}

inline void AutomationProperties::SetAcceleratorKey(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetAcceleratorKey(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::AccessKeyProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.AccessKeyProperty(); });
}

inline hstring AutomationProperties::GetAccessKey(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetAccessKey(element); });
}

inline void AutomationProperties::SetAccessKey(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetAccessKey(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::AutomationIdProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.AutomationIdProperty(); });
}

inline hstring AutomationProperties::GetAutomationId(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetAutomationId(element); });
}

inline void AutomationProperties::SetAutomationId(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetAutomationId(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::HelpTextProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.HelpTextProperty(); });
}

inline hstring AutomationProperties::GetHelpText(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetHelpText(element); });
}

inline void AutomationProperties::SetHelpText(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetHelpText(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::IsRequiredForFormProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.IsRequiredForFormProperty(); });
}

inline bool AutomationProperties::GetIsRequiredForForm(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetIsRequiredForForm(element); });
}

inline void AutomationProperties::SetIsRequiredForForm(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetIsRequiredForForm(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::ItemStatusProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.ItemStatusProperty(); });
}

inline hstring AutomationProperties::GetItemStatus(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetItemStatus(element); });
}

inline void AutomationProperties::SetItemStatus(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetItemStatus(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::ItemTypeProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.ItemTypeProperty(); });
}

inline hstring AutomationProperties::GetItemType(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetItemType(element); });
}

inline void AutomationProperties::SetItemType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetItemType(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LabeledByProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.LabeledByProperty(); });
}

inline Windows::UI::Xaml::UIElement AutomationProperties::GetLabeledBy(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetLabeledBy(element); });
}

inline void AutomationProperties::SetLabeledBy(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::UIElement const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetLabeledBy(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::NameProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.NameProperty(); });
}

inline hstring AutomationProperties::GetName(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetName(element); });
}

inline void AutomationProperties::SetName(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetName(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LiveSettingProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.LiveSettingProperty(); });
}

inline Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting AutomationProperties::GetLiveSetting(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.GetLiveSetting(element); });
}

inline void AutomationProperties::SetLiveSetting(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationLiveSetting const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics>([&](auto&& f) { return f.SetLiveSetting(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::AccessibilityViewProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>([&](auto&& f) { return f.AccessibilityViewProperty(); });
}

inline Windows::UI::Xaml::Automation::Peers::AccessibilityView AutomationProperties::GetAccessibilityView(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>([&](auto&& f) { return f.GetAccessibilityView(element); });
}

inline void AutomationProperties::SetAccessibilityView(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AccessibilityView const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>([&](auto&& f) { return f.SetAccessibilityView(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::ControlledPeersProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>([&](auto&& f) { return f.ControlledPeersProperty(); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::UIElement> AutomationProperties::GetControlledPeers(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2>([&](auto&& f) { return f.GetControlledPeers(element); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::PositionInSetProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.PositionInSetProperty(); });
}

inline int32_t AutomationProperties::GetPositionInSet(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.GetPositionInSet(element); });
}

inline void AutomationProperties::SetPositionInSet(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.SetPositionInSet(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::SizeOfSetProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.SizeOfSetProperty(); });
}

inline int32_t AutomationProperties::GetSizeOfSet(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.GetSizeOfSet(element); });
}

inline void AutomationProperties::SetSizeOfSet(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.SetSizeOfSet(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LevelProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.LevelProperty(); });
}

inline int32_t AutomationProperties::GetLevel(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.GetLevel(element); });
}

inline void AutomationProperties::SetLevel(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.SetLevel(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::AnnotationsProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.AnnotationsProperty(); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Automation::AutomationAnnotation> AutomationProperties::GetAnnotations(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3>([&](auto&& f) { return f.GetAnnotations(element); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LandmarkTypeProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.LandmarkTypeProperty(); });
}

inline Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType AutomationProperties::GetLandmarkType(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.GetLandmarkType(element); });
}

inline void AutomationProperties::SetLandmarkType(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationLandmarkType const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.SetLandmarkType(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LocalizedLandmarkTypeProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.LocalizedLandmarkTypeProperty(); });
}

inline hstring AutomationProperties::GetLocalizedLandmarkType(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.GetLocalizedLandmarkType(element); });
}

inline void AutomationProperties::SetLocalizedLandmarkType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4>([&](auto&& f) { return f.SetLocalizedLandmarkType(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::IsPeripheralProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.IsPeripheralProperty(); });
}

inline bool AutomationProperties::GetIsPeripheral(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetIsPeripheral(element); });
}

inline void AutomationProperties::SetIsPeripheral(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.SetIsPeripheral(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::IsDataValidForFormProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.IsDataValidForFormProperty(); });
}

inline bool AutomationProperties::GetIsDataValidForForm(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetIsDataValidForForm(element); });
}

inline void AutomationProperties::SetIsDataValidForForm(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.SetIsDataValidForForm(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::FullDescriptionProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.FullDescriptionProperty(); });
}

inline hstring AutomationProperties::GetFullDescription(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetFullDescription(element); });
}

inline void AutomationProperties::SetFullDescription(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.SetFullDescription(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::LocalizedControlTypeProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.LocalizedControlTypeProperty(); });
}

inline hstring AutomationProperties::GetLocalizedControlType(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetLocalizedControlType(element); });
}

inline void AutomationProperties::SetLocalizedControlType(Windows::UI::Xaml::DependencyObject const& element, param::hstring const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.SetLocalizedControlType(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::DescribedByProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.DescribedByProperty(); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> AutomationProperties::GetDescribedBy(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetDescribedBy(element); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::FlowsToProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.FlowsToProperty(); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> AutomationProperties::GetFlowsTo(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetFlowsTo(element); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::FlowsFromProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.FlowsFromProperty(); });
}

inline Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> AutomationProperties::GetFlowsFrom(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5>([&](auto&& f) { return f.GetFlowsFrom(element); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::CultureProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6>([&](auto&& f) { return f.CultureProperty(); });
}

inline int32_t AutomationProperties::GetCulture(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6>([&](auto&& f) { return f.GetCulture(element); });
}

inline void AutomationProperties::SetCulture(Windows::UI::Xaml::DependencyObject const& element, int32_t value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6>([&](auto&& f) { return f.SetCulture(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::HeadingLevelProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7>([&](auto&& f) { return f.HeadingLevelProperty(); });
}

inline Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel AutomationProperties::GetHeadingLevel(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7>([&](auto&& f) { return f.GetHeadingLevel(element); });
}

inline void AutomationProperties::SetHeadingLevel(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::Automation::Peers::AutomationHeadingLevel const& value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7>([&](auto&& f) { return f.SetHeadingLevel(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty AutomationProperties::IsDialogProperty()
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8>([&](auto&& f) { return f.IsDialogProperty(); });
}

inline bool AutomationProperties::GetIsDialog(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8>([&](auto&& f) { return f.GetIsDialog(element); });
}

inline void AutomationProperties::SetIsDialog(Windows::UI::Xaml::DependencyObject const& element, bool value)
{
    impl::call_factory<AutomationProperties, Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8>([&](auto&& f) { return f.SetIsDialog(element, value); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DockPatternIdentifiers::DockPositionProperty()
{
    return impl::call_factory<DockPatternIdentifiers, Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics>([&](auto&& f) { return f.DockPositionProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DragPatternIdentifiers::DropEffectProperty()
{
    return impl::call_factory<DragPatternIdentifiers, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics>([&](auto&& f) { return f.DropEffectProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DragPatternIdentifiers::DropEffectsProperty()
{
    return impl::call_factory<DragPatternIdentifiers, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics>([&](auto&& f) { return f.DropEffectsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DragPatternIdentifiers::GrabbedItemsProperty()
{
    return impl::call_factory<DragPatternIdentifiers, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics>([&](auto&& f) { return f.GrabbedItemsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DragPatternIdentifiers::IsGrabbedProperty()
{
    return impl::call_factory<DragPatternIdentifiers, Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics>([&](auto&& f) { return f.IsGrabbedProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DropTargetPatternIdentifiers::DropTargetEffectProperty()
{
    return impl::call_factory<DropTargetPatternIdentifiers, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics>([&](auto&& f) { return f.DropTargetEffectProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty DropTargetPatternIdentifiers::DropTargetEffectsProperty()
{
    return impl::call_factory<DropTargetPatternIdentifiers, Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics>([&](auto&& f) { return f.DropTargetEffectsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ExpandCollapsePatternIdentifiers::ExpandCollapseStateProperty()
{
    return impl::call_factory<ExpandCollapsePatternIdentifiers, Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics>([&](auto&& f) { return f.ExpandCollapseStateProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridItemPatternIdentifiers::ColumnProperty()
{
    return impl::call_factory<GridItemPatternIdentifiers, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>([&](auto&& f) { return f.ColumnProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridItemPatternIdentifiers::ColumnSpanProperty()
{
    return impl::call_factory<GridItemPatternIdentifiers, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>([&](auto&& f) { return f.ColumnSpanProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridItemPatternIdentifiers::ContainingGridProperty()
{
    return impl::call_factory<GridItemPatternIdentifiers, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>([&](auto&& f) { return f.ContainingGridProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridItemPatternIdentifiers::RowProperty()
{
    return impl::call_factory<GridItemPatternIdentifiers, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>([&](auto&& f) { return f.RowProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridItemPatternIdentifiers::RowSpanProperty()
{
    return impl::call_factory<GridItemPatternIdentifiers, Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics>([&](auto&& f) { return f.RowSpanProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridPatternIdentifiers::ColumnCountProperty()
{
    return impl::call_factory<GridPatternIdentifiers, Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics>([&](auto&& f) { return f.ColumnCountProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty GridPatternIdentifiers::RowCountProperty()
{
    return impl::call_factory<GridPatternIdentifiers, Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics>([&](auto&& f) { return f.RowCountProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty MultipleViewPatternIdentifiers::CurrentViewProperty()
{
    return impl::call_factory<MultipleViewPatternIdentifiers, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics>([&](auto&& f) { return f.CurrentViewProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty MultipleViewPatternIdentifiers::SupportedViewsProperty()
{
    return impl::call_factory<MultipleViewPatternIdentifiers, Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics>([&](auto&& f) { return f.SupportedViewsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::IsReadOnlyProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.IsReadOnlyProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::LargeChangeProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.LargeChangeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::MaximumProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.MaximumProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::MinimumProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.MinimumProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::SmallChangeProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.SmallChangeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty RangeValuePatternIdentifiers::ValueProperty()
{
    return impl::call_factory<RangeValuePatternIdentifiers, Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::HorizontallyScrollableProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.HorizontallyScrollableProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::HorizontalScrollPercentProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.HorizontalScrollPercentProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::HorizontalViewSizeProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.HorizontalViewSizeProperty(); });
}

inline double ScrollPatternIdentifiers::NoScroll()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.NoScroll(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::VerticallyScrollableProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.VerticallyScrollableProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::VerticalScrollPercentProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.VerticalScrollPercentProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ScrollPatternIdentifiers::VerticalViewSizeProperty()
{
    return impl::call_factory<ScrollPatternIdentifiers, Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics>([&](auto&& f) { return f.VerticalViewSizeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SelectionItemPatternIdentifiers::IsSelectedProperty()
{
    return impl::call_factory<SelectionItemPatternIdentifiers, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics>([&](auto&& f) { return f.IsSelectedProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SelectionItemPatternIdentifiers::SelectionContainerProperty()
{
    return impl::call_factory<SelectionItemPatternIdentifiers, Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics>([&](auto&& f) { return f.SelectionContainerProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SelectionPatternIdentifiers::CanSelectMultipleProperty()
{
    return impl::call_factory<SelectionPatternIdentifiers, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics>([&](auto&& f) { return f.CanSelectMultipleProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SelectionPatternIdentifiers::IsSelectionRequiredProperty()
{
    return impl::call_factory<SelectionPatternIdentifiers, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics>([&](auto&& f) { return f.IsSelectionRequiredProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SelectionPatternIdentifiers::SelectionProperty()
{
    return impl::call_factory<SelectionPatternIdentifiers, Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics>([&](auto&& f) { return f.SelectionProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty SpreadsheetItemPatternIdentifiers::FormulaProperty()
{
    return impl::call_factory<SpreadsheetItemPatternIdentifiers, Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics>([&](auto&& f) { return f.FormulaProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::ExtendedPropertiesProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.ExtendedPropertiesProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::FillColorProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.FillColorProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::FillPatternColorProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.FillPatternColorProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::FillPatternStyleProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.FillPatternStyleProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::ShapeProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.ShapeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::StyleIdProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.StyleIdProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty StylesPatternIdentifiers::StyleNameProperty()
{
    return impl::call_factory<StylesPatternIdentifiers, Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics>([&](auto&& f) { return f.StyleNameProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TableItemPatternIdentifiers::ColumnHeaderItemsProperty()
{
    return impl::call_factory<TableItemPatternIdentifiers, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics>([&](auto&& f) { return f.ColumnHeaderItemsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TableItemPatternIdentifiers::RowHeaderItemsProperty()
{
    return impl::call_factory<TableItemPatternIdentifiers, Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics>([&](auto&& f) { return f.RowHeaderItemsProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TablePatternIdentifiers::ColumnHeadersProperty()
{
    return impl::call_factory<TablePatternIdentifiers, Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics>([&](auto&& f) { return f.ColumnHeadersProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TablePatternIdentifiers::RowHeadersProperty()
{
    return impl::call_factory<TablePatternIdentifiers, Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics>([&](auto&& f) { return f.RowHeadersProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TablePatternIdentifiers::RowOrColumnMajorProperty()
{
    return impl::call_factory<TablePatternIdentifiers, Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics>([&](auto&& f) { return f.RowOrColumnMajorProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TogglePatternIdentifiers::ToggleStateProperty()
{
    return impl::call_factory<TogglePatternIdentifiers, Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics>([&](auto&& f) { return f.ToggleStateProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPattern2Identifiers::CanZoomProperty()
{
    return impl::call_factory<TransformPattern2Identifiers, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics>([&](auto&& f) { return f.CanZoomProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPattern2Identifiers::ZoomLevelProperty()
{
    return impl::call_factory<TransformPattern2Identifiers, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics>([&](auto&& f) { return f.ZoomLevelProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPattern2Identifiers::MaxZoomProperty()
{
    return impl::call_factory<TransformPattern2Identifiers, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics>([&](auto&& f) { return f.MaxZoomProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPattern2Identifiers::MinZoomProperty()
{
    return impl::call_factory<TransformPattern2Identifiers, Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics>([&](auto&& f) { return f.MinZoomProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPatternIdentifiers::CanMoveProperty()
{
    return impl::call_factory<TransformPatternIdentifiers, Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics>([&](auto&& f) { return f.CanMoveProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPatternIdentifiers::CanResizeProperty()
{
    return impl::call_factory<TransformPatternIdentifiers, Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics>([&](auto&& f) { return f.CanResizeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty TransformPatternIdentifiers::CanRotateProperty()
{
    return impl::call_factory<TransformPatternIdentifiers, Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics>([&](auto&& f) { return f.CanRotateProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ValuePatternIdentifiers::IsReadOnlyProperty()
{
    return impl::call_factory<ValuePatternIdentifiers, Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics>([&](auto&& f) { return f.IsReadOnlyProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty ValuePatternIdentifiers::ValueProperty()
{
    return impl::call_factory<ValuePatternIdentifiers, Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics>([&](auto&& f) { return f.ValueProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::CanMaximizeProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.CanMaximizeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::CanMinimizeProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.CanMinimizeProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::IsModalProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.IsModalProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::IsTopmostProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.IsTopmostProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::WindowInteractionStateProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.WindowInteractionStateProperty(); });
}

inline Windows::UI::Xaml::Automation::AutomationProperty WindowPatternIdentifiers::WindowVisualStateProperty()
{
    return impl::call_factory<WindowPatternIdentifiers, Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics>([&](auto&& f) { return f.WindowVisualStateProperty(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAnnotationPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotationFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotationFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotationStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationAnnotationStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationElementIdentifiersStatics8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationProperties> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationProperties> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationPropertiesStatics8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IAutomationProperty> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IAutomationProperty> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDockPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDockPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDockPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDragPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDragPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDragPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IDropTargetPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IExpandCollapsePatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IGridItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IGridItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IGridItemPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IGridPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IGridPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IGridPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IMultipleViewPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IRangeValuePatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IScrollPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IScrollPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IScrollPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISelectionItemPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISelectionPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISelectionPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISelectionPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ISpreadsheetItemPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IStylesPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IStylesPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IStylesPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITableItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITableItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITableItemPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITablePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITablePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITablePatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITogglePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITogglePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITogglePatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITransformPattern2Identifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITransformPattern2Identifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITransformPattern2IdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITransformPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITransformPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ITransformPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IValuePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IValuePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IValuePatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IWindowPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IWindowPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::IWindowPatternIdentifiersStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::AnnotationPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::AnnotationPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::AutomationAnnotation> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::AutomationAnnotation> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::AutomationElementIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::AutomationElementIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::AutomationProperties> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::AutomationProperties> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::AutomationProperty> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::AutomationProperty> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::DockPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::DockPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::DragPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::DragPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::DropTargetPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::DropTargetPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ExpandCollapsePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ExpandCollapsePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::GridItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::GridItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::GridPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::GridPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::MultipleViewPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::MultipleViewPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::RangeValuePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::RangeValuePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ScrollPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ScrollPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::SelectionItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::SelectionItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::SelectionPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::SelectionPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::SpreadsheetItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::SpreadsheetItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::StylesPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::StylesPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::TableItemPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::TableItemPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::TablePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::TablePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::TogglePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::TogglePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::TransformPattern2Identifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::TransformPattern2Identifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::TransformPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::TransformPatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::ValuePatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::ValuePatternIdentifiers> {};
template<> struct hash<winrt::Windows::UI::Xaml::Automation::WindowPatternIdentifiers> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Automation::WindowPatternIdentifiers> {};

}
